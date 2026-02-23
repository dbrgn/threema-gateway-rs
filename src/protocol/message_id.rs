//! Message ID related types.

use std::{fmt, str::FromStr};

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::errors::EmptyListError;

/// Errors when parsing a [`MessageId`] from a hex string.
#[derive(Debug, PartialEq, Clone, Error)]
pub enum MessageIdParseError {
    /// Hex string has wrong length (expected 16 characters)
    #[error("invalid hex length (expected 16, got {0})")]
    InvalidLength(usize),

    /// Hex string contains invalid characters
    #[error("invalid hex: {0}")]
    InvalidHex(data_encoding::DecodeError),
}

/// A Threema message ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId(u64);

impl MessageId {
    /// Create a new [`MessageId`] from a raw `u64`.
    #[must_use]
    pub fn from_u64(id: u64) -> Self {
        Self(id)
    }

    /// Parse a [`MessageId`] from a 16-character hexadecimal string (little-endian byte order).
    pub fn from_hex_le(hex: &str) -> Result<Self, MessageIdParseError> {
        if hex.len() != 16 {
            return Err(MessageIdParseError::InvalidLength(hex.len()));
        }
        let bytes = HEXLOWER_PERMISSIVE
            .decode(hex.as_bytes())
            .map_err(MessageIdParseError::InvalidHex)?;
        Ok(Self(u64::from_le_bytes(bytes.try_into().expect("8 bytes"))))
    }

    /// Return the underlying `u64` value.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Encode this message ID as a 16-character lowercase hexadecimal string (little-endian byte
    /// order).
    #[must_use]
    pub fn to_hex_le(self) -> String {
        HEXLOWER.encode(&self.0.to_le_bytes())
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MessageId({self})")
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex_le())
    }
}

impl FromStr for MessageId {
    type Err = MessageIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex_le(s)
    }
}

impl Serialize for MessageId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex_le())
    }
}

impl<'de> Deserialize<'de> for MessageId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        Self::from_hex_le(&hex).map_err(serde::de::Error::custom)
    }
}

/// A non-empty collection of [`MessageId`]s.
///
/// This newtype guarantees at construction time that at least one message ID is
/// present, making it impossible to represent an empty list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageIds {
    /// Invariant: always contains at least one element.
    ids: Vec<MessageId>,
}

impl MessageIds {
    /// Create a new [`MessageIds`] containing a single message ID.
    #[must_use]
    pub fn new(id: MessageId) -> Self {
        Self { ids: vec![id] }
    }

    /// Create a new [`MessageIds`] from a slice.
    ///
    /// Returns an error if the slice is empty.
    pub fn from_slice(ids: &[MessageId]) -> Result<Self, EmptyListError> {
        if ids.is_empty() {
            return Err(EmptyListError);
        }
        Ok(Self { ids: ids.to_vec() })
    }

    /// Return the contained message IDs as a slice.
    ///
    /// The returned slice is guaranteed to be non-empty.
    #[must_use]
    pub fn as_slice(&self) -> &[MessageId] {
        &self.ids
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::EmptyListError,
        protocol::message_id::{MessageId, MessageIdParseError, MessageIds},
    };

    #[test]
    fn from_u64() {
        let id = MessageId::from_u64(42);
        assert_eq!(id.as_u64(), 42);
    }

    #[test]
    fn from_hex_le_lowercase() {
        let id = MessageId::from_hex_le("0102030405060708").unwrap();
        assert_eq!(id.as_u64(), 0x0807_0605_0403_0201);
    }

    #[test]
    fn from_hex_le_mixed_case() {
        let id = MessageId::from_hex_le("010203040506feff").unwrap();
        let id_upper = MessageId::from_hex_le("010203040506FEFF").unwrap();
        assert_eq!(id, id_upper);

        let id_mixed = MessageId::from_hex_le("010203040506feFF").unwrap();
        assert_eq!(id, id_mixed);
    }

    #[test]
    fn from_hex_le_too_short() {
        let err = MessageId::from_hex_le("01020304050607").unwrap_err();
        assert_eq!(err, MessageIdParseError::InvalidLength(14));
    }

    #[test]
    fn from_hex_le_too_long() {
        let err = MessageId::from_hex_le("010203040506070809").unwrap_err();
        assert_eq!(err, MessageIdParseError::InvalidLength(18));
    }

    #[test]
    fn from_hex_le_empty() {
        let err = MessageId::from_hex_le("").unwrap_err();
        assert_eq!(err, MessageIdParseError::InvalidLength(0));
    }

    #[test]
    fn from_hex_le_invalid_chars() {
        let err = MessageId::from_hex_le("010203040506070g").unwrap_err();
        assert!(
            matches!(err, MessageIdParseError::InvalidHex(_)),
            "expected InvalidHex, got {err:?}"
        );
    }

    #[test]
    fn to_hex_le() {
        let id = MessageId::from_u64(0xff07_0605_0403_0201);
        assert_eq!(id.to_hex_le(), "01020304050607ff");
    }

    #[test]
    fn to_hex_le_zero() {
        let id = MessageId::from_u64(0);
        assert_eq!(id.to_hex_le(), "0000000000000000");
    }

    #[test]
    fn to_hex_le_max() {
        let id = MessageId::from_u64(u64::MAX);
        assert_eq!(id.to_hex_le(), "ffffffffffffffff");
    }

    #[test]
    fn display() {
        let id = MessageId::from_u64(0x0807_0605_0403_0201);
        assert_eq!(format!("{id}"), "0102030405060708");
    }

    #[test]
    fn from_str() {
        let id: MessageId = "0102030405060708".parse().unwrap();
        assert_eq!(id.as_u64(), 0x0807_0605_0403_0201);
    }

    #[test]
    fn round_trip_hex() {
        let original = MessageId::from_u64(0xDEAD_BEEF_CAFE_F000);
        let hex = original.to_hex_le();
        let restored = MessageId::from_hex_le(&hex).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn round_trip_u64() {
        let value = 0x0123_4567_89AB_CDEF;
        let id = MessageId::from_u64(value);
        assert_eq!(id.as_u64(), value);
    }

    #[test]
    fn serde_serialize_deserialize() {
        let id = MessageId::from_u64(0x0807_0605_0403_0201);

        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"0102030405060708\"");

        let deserialized: MessageId = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, id);
    }

    mod message_ids {
        use super::*;

        /// Shorthand for creating a [`MessageId`] in tests.
        fn mid(value: u64) -> MessageId {
            MessageId::from_u64(value)
        }

        mod new {
            use super::*;

            #[test]
            fn single_element() {
                let ids = MessageIds::new(mid(42));
                assert_eq!(ids.as_slice(), &[mid(42)]);
            }
        }

        mod from_slice {
            use super::*;

            #[test]
            fn single_element() {
                let ids =
                    MessageIds::from_slice(&[mid(1)]).expect("single-element slice should succeed");
                assert_eq!(ids.as_slice(), &[mid(1)]);
            }

            #[test]
            fn multiple_elements() {
                let ids = MessageIds::from_slice(&[mid(1), mid(2), mid(3)])
                    .expect("multi-element slice should succeed");
                assert_eq!(ids.as_slice(), &[mid(1), mid(2), mid(3)]);
            }

            #[test]
            fn empty_returns_error() {
                let err = MessageIds::from_slice(&[]).unwrap_err();
                assert_eq!(err, EmptyListError);
            }
        }
    }
}
