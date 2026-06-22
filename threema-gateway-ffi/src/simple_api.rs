//! Threema Gateway Simple API (without end-to-end encryption).

use std::sync::Arc;

use threema_gateway as lib;

use crate::{
    errors::ApiError,
    lookup::{Capabilities, LookupCriterion},
    recipient::{Recipient, RecipientKey},
    threema_id::ThreemaId,
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
    fn new(id: &ThreemaId, secret: String) -> Arc<Self> {
        Arc::new(Self {
            inner: lib::ApiBuilder::new(id.inner, secret).into_simple(),
        })
    }

    /// Create a new Simple API instance with a custom endpoint URL.
    #[uniffi::constructor]
    fn new_with_endpoint(id: &ThreemaId, secret: String, endpoint: String) -> Arc<Self> {
        Arc::new(Self {
            inner: lib::ApiBuilder::new(id.inner, secret)
                .with_custom_endpoint(endpoint)
                .into_simple(),
        })
    }

    /// Send a message to the specified recipient in basic mode.
    ///
    /// Returns the message ID on success.
    async fn send(&self, to: Recipient, text: String) -> Result<String, ApiError> {
        let recipient = lib::Recipient::from(to);
        Ok(self.inner.send(&recipient, &text).await?.to_string())
    }

    /// Fetch the public key for the specified Threema ID.
    async fn lookup_pubkey(&self, id: &ThreemaId) -> Result<RecipientKey, ApiError> {
        Ok(self.inner.lookup_pubkey(&id.inner).await?.into())
    }

    /// Look up a Threema ID in the directory by phone number or e-mail.
    async fn lookup_id(&self, criterion: LookupCriterion) -> Result<Arc<ThreemaId>, ApiError> {
        let criterion = lib::LookupCriterion::from(criterion);
        let lib_id = self.inner.lookup_id(&criterion).await?;
        Ok(Arc::new(ThreemaId::from(lib_id)))
    }

    /// Look up the capabilities of a Threema ID.
    async fn lookup_capabilities(&self, id: &ThreemaId) -> Result<Capabilities, ApiError> {
        Ok(self.inner.lookup_capabilities(&id.inner).await?.into())
    }

    /// Look up remaining gateway credits.
    async fn lookup_credits(&self) -> Result<i64, ApiError> {
        Ok(self.inner.lookup_credits().await?)
    }
}
