//! Cache-related functionality.
//!
//! Note: Concrete implementations are provided behind feature flags:
//!
//! - `public-key-cache-inmemory`: An in-memory public key cache backed by moka
//! - `public-key-cache-redis`: A public key cache backed by Redis

use core::future::Future;

use crate::crypto::RecipientKey;

#[cfg(feature = "public-key-cache-inmemory")]
mod in_memory;
#[cfg(feature = "public-key-cache-redis")]
mod redis;

#[cfg(feature = "public-key-cache-inmemory")]
pub use in_memory::{InMemoryPublicKeyCache, InMemoryPublicKeyCacheError};
#[cfg(feature = "public-key-cache-redis")]
pub use redis::{RedisPublicKeyCache, RedisPublicKeyCacheError};

/// A cache for Threema public keys
pub trait PublicKeyCache {
    /// Error returned if cache operations fail
    type Error: core::error::Error;

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
