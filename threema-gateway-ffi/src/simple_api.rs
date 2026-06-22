//! Threema Gateway Simple API (without end-to-end encryption).

use std::{future::Future, sync::Arc};

use threema_gateway as lib;

use crate::{
    errors::ApiError,
    lookup::{Capabilities, LookupCriterion},
    recipient::{Recipient, RecipientKey},
};

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
