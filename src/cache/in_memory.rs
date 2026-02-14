//! In-memory public key cache backed by moka.

use std::time::Duration;

use moka::future::Cache;
use thiserror::Error;

use crate::{PublicKeyCache, RecipientKey, errors::CryptoError};

/// Errors when interacting with the [`InMemoryPublicKeyCache`].
#[derive(Debug, Error)]
pub enum InMemoryPublicKeyCacheError {
    /// Cache contained an entry that could not be decoded as [`RecipientKey`]
    #[error("invalid recipient key for {identity} encountered in cache: {error}")]
    CorruptedCache {
        /// Identity for which the lookup failed
        identity: String,
        /// Underlying error
        error: CryptoError,
    },
}

/// In-memory public key cache backed by [`moka`].
///
/// The cache has a max capacity and a TTL.
///
/// Requires the `public-key-cache-inmemory` Cargo feature to be enabled.
pub struct InMemoryPublicKeyCache {
    cache: Cache<String, Vec<u8>>,
}

impl InMemoryPublicKeyCache {
    /// Create a new in-memory public key cache with custom capacity and TTL.
    #[must_use]
    pub fn new(max_capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();
        Self { cache }
    }
}

impl PublicKeyCache for InMemoryPublicKeyCache {
    type Error = InMemoryPublicKeyCacheError;

    async fn store(&self, identity: &str, key: &RecipientKey) -> Result<(), Self::Error> {
        self.cache
            .insert(identity.to_owned(), key.as_bytes().to_vec())
            .await;
        Ok(())
    }

    async fn load(&self, identity: &str) -> Result<Option<RecipientKey>, Self::Error> {
        match self.cache.get(identity).await {
            Some(key_bytes) => {
                let recipient_key = RecipientKey::from_bytes(&key_bytes).map_err(|error| {
                    InMemoryPublicKeyCacheError::CorruptedCache {
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

#[cfg(test)]
mod tests {
    use std::{str::FromStr as _, time::Duration};

    use super::*;

    /// Helper to create a test `RecipientKey` from a hex string
    fn test_key(hex: &str) -> RecipientKey {
        RecipientKey::from_str(hex).expect("Failed to create test key")
    }

    mod store {
        use super::*;

        #[tokio::test]
        async fn stores_key_successfully() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));
            let key = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");

            let result = cache.store("TESTID01", &key).await;
            assert!(result.is_ok());

            // Sync the cache to ensure entry count is updated
            cache.cache.run_pending_tasks().await;
            assert_eq!(cache.cache.entry_count(), 1);
        }

        #[tokio::test]
        async fn overwrites_existing_key() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));
            let key1 = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");
            let key2 = test_key("ff000000000000000000000000000000000000000000000000000000000000ee");

            cache.store("TESTID01", &key1).await.unwrap();
            cache.store("TESTID01", &key2).await.unwrap();

            // Sync the cache to ensure entry count is updated
            cache.cache.run_pending_tasks().await;

            // Should still only have 1 entry
            assert_eq!(cache.cache.entry_count(), 1);

            // Should have the second key
            let loaded = cache.load("TESTID01").await.unwrap();
            assert_eq!(loaded, Some(key2));
        }

        #[tokio::test]
        async fn stores_multiple_different_identities() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));
            let key1 = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");
            let key2 = test_key("ff000000000000000000000000000000000000000000000000000000000000ee");
            let key3 = test_key("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

            cache.store("TESTID01", &key1).await.unwrap();
            cache.store("TESTID02", &key2).await.unwrap();
            cache.store("TESTID03", &key3).await.unwrap();

            // Sync the cache to ensure entry count is updated
            cache.cache.run_pending_tasks().await;
            assert_eq!(cache.cache.entry_count(), 3);
        }
    }

    mod load {
        use super::*;

        #[tokio::test]
        async fn returns_none_for_nonexistent_key() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));
            let result = cache.load("NONEXIST").await.unwrap();
            assert_eq!(result, None);
        }

        #[tokio::test]
        async fn loads_stored_key() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));
            let key = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");

            cache.store("TESTID01", &key).await.unwrap();
            let loaded = cache.load("TESTID01").await.unwrap();

            assert_eq!(loaded, Some(key));
        }

        #[tokio::test]
        async fn loads_correct_key_for_identity() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));
            let key1 = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");
            let key2 = test_key("ff000000000000000000000000000000000000000000000000000000000000ee");

            cache.store("TESTID01", &key1).await.unwrap();
            cache.store("TESTID02", &key2).await.unwrap();

            let loaded1 = cache.load("TESTID01").await.unwrap();
            let loaded2 = cache.load("TESTID02").await.unwrap();

            assert_eq!(loaded1, Some(key1));
            assert_eq!(loaded2, Some(key2));
        }

        #[tokio::test]
        async fn returns_error_for_corrupted_cache() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));

            // Manually insert invalid data into the cache
            cache
                .cache
                .insert("CORRUPT".to_owned(), vec![1, 2, 3])
                .await;

            let result = cache.load("CORRUPT").await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                InMemoryPublicKeyCacheError::CorruptedCache { .. }
            ));
        }

        #[tokio::test]
        async fn returns_none_after_ttl_expires() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_millis(100));
            let key = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");

            cache.store("TESTID01", &key).await.unwrap();

            // Wait for TTL to expire
            tokio::time::sleep(Duration::from_millis(150)).await;

            let loaded = cache.load("TESTID01").await.unwrap();
            assert_eq!(loaded, None);
        }
    }

    mod capacity {
        use super::*;

        #[tokio::test]
        async fn respects_max_capacity() {
            let cache = InMemoryPublicKeyCache::new(2, Duration::from_secs(60));
            let key1 = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");
            let key2 = test_key("ff000000000000000000000000000000000000000000000000000000000000ee");
            let key3 = test_key("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

            cache.store("TESTID01", &key1).await.unwrap();
            cache.store("TESTID02", &key2).await.unwrap();
            cache.store("TESTID03", &key3).await.unwrap();

            // Should not exceed capacity
            cache.cache.run_pending_tasks().await;
            assert!(cache.cache.entry_count() <= 2);
        }
    }

    mod integration {
        use super::*;

        #[tokio::test]
        async fn store_and_load_roundtrip() {
            let cache = InMemoryPublicKeyCache::new(100, Duration::from_secs(3600));
            let key = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");

            // Store key
            cache.store("TESTID01", &key).await.unwrap();

            // Load key
            let loaded = cache.load("TESTID01").await.unwrap().unwrap();

            // Verify bytes are identical
            assert_eq!(key.as_bytes(), loaded.as_bytes());
        }

        #[tokio::test]
        async fn multiple_operations() {
            let cache = InMemoryPublicKeyCache::new(100, Duration::from_secs(3600));
            let key1 = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");
            let key2 = test_key("ff000000000000000000000000000000000000000000000000000000000000ee");

            // Store first key
            cache.store("ALICE___", &key1).await.unwrap();

            // Load first key
            let loaded1 = cache.load("ALICE___").await.unwrap();
            assert_eq!(loaded1, Some(key1.clone()));

            // Store second key with different identity
            cache.store("BOB_____", &key2).await.unwrap();

            // Load both keys
            let loaded1 = cache.load("ALICE___").await.unwrap();
            let loaded2 = cache.load("BOB_____").await.unwrap();

            assert_eq!(loaded1, Some(key1));
            assert_eq!(loaded2, Some(key2.clone()));

            // Update first key
            cache.store("ALICE___", &key2).await.unwrap();
            let updated = cache.load("ALICE___").await.unwrap();
            assert_eq!(updated, Some(key2));
        }

        #[tokio::test]
        async fn handles_empty_identity() {
            let cache = InMemoryPublicKeyCache::new(10, Duration::from_secs(60));
            let key = test_key("5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0");

            cache.store("", &key).await.unwrap();
            let loaded = cache.load("").await.unwrap();

            assert_eq!(loaded, Some(key));
        }
    }
}
