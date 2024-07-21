use std::future::Future;

use crate::crypto::RecipientKey;

/// A cache for Threema public keys
pub trait PublicKeyCache {
    /// Error returned if cache operations fail
    type Error: std::error::Error;

    /// Store a public key for `identity` in the cache
    fn store(
        &self,
        identity: &str,
        key: &RecipientKey,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Retrieve a public key for `identity` from the cache
    fn load(
        &self,
        identity: &str,
    ) -> impl Future<Output = Result<Option<RecipientKey>, Self::Error>>;
}
