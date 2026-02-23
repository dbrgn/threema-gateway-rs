//! Redis-backed public key cache.

use std::time::Duration;

use redis::{AsyncCommands as _, aio::ConnectionLike};
use thiserror::Error;

use crate::{cache::PublicKeyCache, crypto::RecipientKey, errors::CryptoError};

/// Errors when interacting with the [`RedisPublicKeyCache`].
#[derive(Debug, Error)]
pub enum RedisPublicKeyCacheError {
    /// Cache contained an entry that could not be decoded as [`RecipientKey`]
    #[error("invalid recipient key for {identity} encountered in cache: {error}")]
    CorruptedCache {
        /// Identity for which the lookup failed
        identity: String,
        /// Underlying error
        error: CryptoError,
    },
    /// Redis operation failed
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
}

/// Redis-backed public key cache.
///
/// Keys are stored with a configurable prefix and optional TTL.
///
/// Requires the `public-key-cache-redis` Cargo feature to be enabled.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use threema_gateway::{ApiBuilder, cache::RedisPublicKeyCache};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Connect to Redis
/// let client = redis::Client::open("redis://127.0.0.1:6379")?;
/// let connection = client.get_multiplexed_async_connection().await?;
///
/// // Create cache with 1 hour TTL
/// let cache = RedisPublicKeyCache::new(
///     connection,
///     "threema:pubkey:",
///     Some(Duration::from_secs(3600)),
/// );
///
/// // Use with the Threema Gateway API
/// let api = ApiBuilder::new("YOUR_GATEWAY_ID", "YOUR_API_SECRET").into_simple();
/// let pubkey = api.lookup_pubkey_with_cache("ECHOECHO", &cache).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Direct cache usage
///
/// ```no_run
/// use std::time::Duration;
/// use threema_gateway::{RecipientKey, cache::{PublicKeyCache, RedisPublicKeyCache}};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let client = redis::Client::open("redis://127.0.0.1:6379")?;
/// let connection = client.get_multiplexed_async_connection().await?;
///
/// // Create cache without expiration (keys never expire)
/// let cache = RedisPublicKeyCache::new(connection, "threema:pubkey:", None);
///
/// // Store and load keys directly
/// # let some_key = RecipientKey::from_bytes(&[0u8; 32])?;
/// cache.store("TESTID01", &some_key).await?;
/// let loaded = cache.load("TESTID01").await?;
/// # Ok(())
/// # }
/// ```
pub struct RedisPublicKeyCache<C> {
    connection: C,
    key_prefix: String,
    ttl: Option<Duration>,
}

impl<C> RedisPublicKeyCache<C> {
    /// Create a new Redis public key cache.
    ///
    /// - `connection`: A Redis async connection (e.g., `MultiplexedConnection`)
    /// - `key_prefix`: Prefix for all cache keys (e.g., `"threema:pubkey:"`)
    /// - `ttl`: Optional TTL for cached keys. `None` means no expiration.
    #[must_use]
    pub fn new<P>(connection: C, key_prefix: P, ttl: Option<Duration>) -> Self
    where
        P: Into<String>,
    {
        Self {
            connection,
            key_prefix: key_prefix.into(),
            ttl,
        }
    }

    /// Build the full Redis key for an identity.
    fn cache_key(&self, identity: &str) -> String {
        format!("{}{identity}", self.key_prefix)
    }
}

impl<C> PublicKeyCache for RedisPublicKeyCache<C>
where
    C: ConnectionLike + Clone + Send + Sync,
{
    type Error = RedisPublicKeyCacheError;

    async fn store(&self, identity: &str, key: &RecipientKey) -> Result<(), Self::Error> {
        let cache_key = self.cache_key(identity);
        let key_bytes = key.as_bytes().to_vec();
        let mut conn = self.connection.clone();
        match self.ttl {
            Some(ttl) => {
                let seconds = ttl.as_secs();
                let _: () = conn.set_ex(cache_key, key_bytes, seconds).await?;
            }
            None => {
                let _: () = conn.set(cache_key, key_bytes).await?;
            }
        }
        Ok(())
    }

    async fn load(&self, identity: &str) -> Result<Option<RecipientKey>, Self::Error> {
        let cache_key = self.cache_key(identity);

        let mut conn = self.connection.clone();
        let result: Option<Vec<u8>> = conn.get(&cache_key).await?;

        match result {
            Some(key_bytes) => {
                let recipient_key = RecipientKey::from_bytes(&key_bytes).map_err(|error| {
                    RedisPublicKeyCacheError::CorruptedCache {
                        identity: identity.to_owned(),
                        error,
                    }
                })?;
                Ok(Some(recipient_key))
            }
            None => Ok(None),
        }
    }
}
