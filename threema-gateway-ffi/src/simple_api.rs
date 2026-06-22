//! Threema Gateway Simple API (without end-to-end encryption).

use std::sync::Arc;

use threema_gateway as lib;

use crate::{
    errors::ApiError,
    lookup::{Capabilities, LookupCriterion},
    recipient::{Recipient, RecipientKey},
};

/// Threema Gateway Simple API (without end-to-end encryption).
#[derive(uniffi::Object)]
pub struct SimpleApi {
    inner: lib::SimpleApi,
}

#[uniffi::export(async_runtime = "tokio")]
impl SimpleApi {
    /// Create a new Simple API instance.
    #[uniffi::constructor]
    fn new(id: &str, secret: String) -> Result<Arc<Self>, ApiError> {
        Ok(Arc::new(Self {
            inner: lib::ApiBuilder::new(id.parse()?, secret).into_simple(),
        }))
    }

    /// Create a new Simple API instance with a custom endpoint URL.
    #[uniffi::constructor]
    fn new_with_endpoint(
        id: &str,
        secret: String,
        endpoint: String,
    ) -> Result<Arc<Self>, ApiError> {
        Ok(Arc::new(Self {
            inner: lib::ApiBuilder::new(id.parse()?, secret)
                .with_custom_endpoint(endpoint)
                .into_simple(),
        }))
    }

    /// Send a message to the specified recipient in basic mode.
    ///
    /// Returns the message ID on success.
    async fn send(&self, to: Recipient, text: String) -> Result<String, ApiError> {
        let recipient = lib::Recipient::try_from(to)?;
        Ok(self.inner.send(&recipient, &text).await?.to_string())
    }

    /// Fetch the public key for the specified Threema ID.
    async fn lookup_pubkey(&self, id: String) -> Result<RecipientKey, ApiError> {
        let id: lib::ThreemaId = id.parse()?;
        Ok(self.inner.lookup_pubkey(&id).await?.into())
    }

    /// Look up a Threema ID in the directory by phone number or e-mail.
    async fn lookup_id(&self, criterion: LookupCriterion) -> Result<String, ApiError> {
        let criterion = lib::LookupCriterion::from(criterion);
        Ok(self.inner.lookup_id(&criterion).await?.to_string())
    }

    /// Look up the capabilities of a Threema ID.
    async fn lookup_capabilities(&self, id: String) -> Result<Capabilities, ApiError> {
        let id: lib::ThreemaId = id.parse()?;
        Ok(self.inner.lookup_capabilities(&id).await?.into())
    }

    /// Look up remaining gateway credits.
    async fn lookup_credits(&self) -> Result<i64, ApiError> {
        Ok(self.inner.lookup_credits().await?)
    }
}
