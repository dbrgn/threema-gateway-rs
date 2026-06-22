//! `UniFFI` bindings for the Threema Gateway SDK.

use std::{future::Future, sync::Arc};

use threema_gateway as lib;

uniffi::setup_scaffolding!();

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors when interacting with the API.
///
/// This is a flat error type, i.e. variant payloads are not exposed to the
/// foreign side. Instead, the `Display` representation is used.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ApiError {
    /// See [`lib::errors::ApiError`].
    #[error("{0}")]
    Api(#[from] lib::errors::ApiError),

    /// Invalid Threema ID passed from the foreign side.
    #[error("invalid Threema ID: {0}")]
    InvalidThreemaId(#[from] lib::ThreemaIdError),
}

// ── Enums ───────────────────────────────────────────────────────────────────

/// Different ways to specify a message recipient in basic mode.
#[derive(uniffi::Enum)]
#[expect(missing_docs, reason = "UniFFI enum variant fields")]
pub enum Recipient {
    /// Recipient identity (8 characters).
    Id { id: String },
    /// Recipient phone number (E.164), without leading +.
    Phone { phone: String },
    /// Recipient e-mail address.
    Email { email: String },
}

impl TryFrom<Recipient> for lib::Recipient<'static> {
    type Error = lib::ThreemaIdError;

    fn try_from(val: Recipient) -> Result<Self, Self::Error> {
        Ok(match val {
            Recipient::Id { id } => lib::Recipient::new_id(id.parse()?),
            Recipient::Phone { phone } => lib::Recipient::new_phone(phone),
            Recipient::Email { email } => lib::Recipient::new_email(email),
        })
    }
}

/// Different ways to look up a Threema ID in the directory.
#[derive(uniffi::Enum)]
#[expect(missing_docs, reason = "UniFFI enum variant fields")]
pub enum LookupCriterion {
    /// The phone number in E.164 format, without the leading `+`.
    Phone { phone: String },
    /// HMAC-SHA256 hash of the E.164 phone number.
    PhoneHash { phone_hash: String },
    /// The e-mail address.
    Email { email: String },
    /// HMAC-SHA256 hash of the lowercased, trimmed e-mail address.
    EmailHash { email_hash: String },
}

impl From<LookupCriterion> for lib::LookupCriterion {
    fn from(val: LookupCriterion) -> Self {
        match val {
            LookupCriterion::Phone { phone } => lib::LookupCriterion::Phone(phone),
            LookupCriterion::PhoneHash { phone_hash } => {
                lib::LookupCriterion::PhoneHash(phone_hash)
            }
            LookupCriterion::Email { email } => lib::LookupCriterion::Email(email),
            LookupCriterion::EmailHash { email_hash } => {
                lib::LookupCriterion::EmailHash(email_hash)
            }
        }
    }
}

// ── Records ─────────────────────────────────────────────────────────────────

/// A Threema ID's public key (32 bytes).
#[derive(uniffi::Record)]
pub struct RecipientKey {
    /// The raw public key bytes.
    pub bytes: Vec<u8>,
}

impl From<lib::RecipientKey> for RecipientKey {
    fn from(val: lib::RecipientKey) -> Self {
        Self {
            bytes: val.as_bytes().to_vec(),
        }
    }
}

/// Capabilities of a Threema ID.
#[derive(uniffi::Record)]
#[expect(clippy::struct_excessive_bools, reason = "Matches upstream type")]
pub struct Capabilities {
    /// Whether the ID can receive text messages.
    pub text: bool,
    /// Whether the ID can receive image messages.
    pub image: bool,
    /// Whether the ID can receive video messages.
    pub video: bool,
    /// Whether the ID can receive audio messages.
    pub audio: bool,
    /// Whether the ID can receive file messages.
    pub file: bool,
    /// List of other capabilities this ID has.
    pub other: Vec<String>,
}

impl From<lib::Capabilities> for Capabilities {
    fn from(val: lib::Capabilities) -> Self {
        Self {
            text: val.text,
            image: val.image,
            video: val.video,
            audio: val.audio,
            file: val.file,
            other: val.other,
        }
    }
}

// ── Object ──────────────────────────────────────────────────────────────────

/// Threema Gateway Simple API (without end-to-end encryption).
#[derive(uniffi::Object)]
#[expect(
    clippy::multiple_inherent_impl,
    reason = "UniFFI export requires a separate impl block"
)]
pub struct SimpleApi {
    inner: Arc<lib::SimpleApi>,
    runtime: tokio::runtime::Runtime,
}

impl SimpleApi {
    /// Spawn an async task on the Tokio runtime and await its result.
    ///
    /// This is necessary because `UniFFI` requires futures to be `Send`, but
    /// Tokio's [`EnterGuard`] is `!Send`. By spawning onto the runtime, the
    /// future runs within the Tokio context without holding a guard across
    /// await points.
    async fn spawn<F, T>(&self, future: F) -> T
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.runtime
            .spawn(future)
            .await
            .expect("tokio task panicked")
    }
}

#[uniffi::export]
impl SimpleApi {
    /// Create a new Simple API instance.
    #[uniffi::constructor]
    fn new(id: &str, secret: String) -> Result<Arc<Self>, ApiError> {
        let inner = Arc::new(lib::ApiBuilder::new(id.parse()?, secret).into_simple());
        let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
        Ok(Arc::new(Self { inner, runtime }))
    }

    /// Create a new Simple API instance with a custom endpoint URL.
    #[uniffi::constructor]
    fn new_with_endpoint(
        id: &str,
        secret: String,
        endpoint: String,
    ) -> Result<Arc<Self>, ApiError> {
        let inner = Arc::new(
            lib::ApiBuilder::new(id.parse()?, secret)
                .with_custom_endpoint(endpoint)
                .into_simple(),
        );
        let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
        Ok(Arc::new(Self { inner, runtime }))
    }

    /// Send a message to the specified recipient in basic mode.
    ///
    /// Returns the message ID on success.
    async fn send(&self, to: Recipient, text: String) -> Result<String, ApiError> {
        let api = Arc::clone(&self.inner);
        let recipient = lib::Recipient::try_from(to)?;
        self.spawn(async move { Ok(api.send(&recipient, &text).await?.to_string()) })
            .await
    }

    /// Fetch the public key for the specified Threema ID.
    async fn lookup_pubkey(&self, id: String) -> Result<RecipientKey, ApiError> {
        let api = Arc::clone(&self.inner);
        let id: lib::ThreemaId = id.parse()?;
        self.spawn(async move { Ok(api.lookup_pubkey(&id).await?.into()) })
            .await
    }

    /// Look up a Threema ID in the directory by phone number or e-mail.
    async fn lookup_id(&self, criterion: LookupCriterion) -> Result<String, ApiError> {
        let api = Arc::clone(&self.inner);
        self.spawn(async move {
            let criterion = lib::LookupCriterion::from(criterion);
            Ok(api.lookup_id(&criterion).await?.to_string())
        })
        .await
    }

    /// Look up the capabilities of a Threema ID.
    async fn lookup_capabilities(&self, id: String) -> Result<Capabilities, ApiError> {
        let api = Arc::clone(&self.inner);
        let id: lib::ThreemaId = id.parse()?;
        self.spawn(async move { Ok(api.lookup_capabilities(&id).await?.into()) })
            .await
    }

    /// Look up remaining gateway credits.
    async fn lookup_credits(&self) -> Result<i64, ApiError> {
        let api = Arc::clone(&self.inner);
        self.spawn(async move { Ok(api.lookup_credits().await?) })
            .await
    }
}
