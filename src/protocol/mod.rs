//! Types related to the Threema messaging protocol.

use std::{fmt, str::FromStr};

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::ApiError;

pub mod e2e;

/// A 16-byte blob ID.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlobId(pub [u8; 16]);

impl BlobId {
    /// Create a new [`BlobId`].
    #[must_use]
    pub fn new(id: [u8; 16]) -> Self {
        BlobId(id)
    }
}

impl FromStr for BlobId {
    type Err = ApiError;

    /// Create a new [`BlobId`] from a 32 character hexadecimal String.
    fn from_str(id: &str) -> Result<Self, Self::Err> {
        let bytes = HEXLOWER_PERMISSIVE
            .decode(id.as_bytes())
            .map_err(|_| ApiError::BadBlobId)?;
        let arr: [u8; 16] = bytes.try_into().map_err(|_| ApiError::BadBlobId)?;
        Ok(BlobId(arr))
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

impl Serialize for BlobId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&HEXLOWER.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let str = String::deserialize(deserializer)?;
        BlobId::from_str(&str).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod blob_id {
        use super::*;

        #[test]
        fn from_str() {
            assert!(BlobId::from_str("0123456789abcdef0123456789abcdef").is_ok());
            assert!(BlobId::from_str("0123456789abcdef0123456789abcdeF").is_ok());
            assert!(BlobId::from_str("0123456789abcdef0123456789abcde").is_err());
            assert!(BlobId::from_str("0123456789abcdef0123456789abcdef\n").is_err());
            assert!(BlobId::from_str("0123456789abcdef0123456789abcdeg").is_err());

            assert_eq!(
                BlobId::from_str("000102030405060708090a0b0c0d0eff").unwrap(),
                BlobId::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xff])
            );
        }

        #[test]
        fn serde_serialize_deserialize() {
            let blob_id = BlobId::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 0xfe, 0xff]);

            let json = serde_json::to_string(&blob_id).unwrap();
            assert_eq!(json, "\"0102030405060708090807060504feff\"");

            let deserialized: BlobId = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, blob_id);
        }
    }
}
