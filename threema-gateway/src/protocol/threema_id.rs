//! Threema ID newtype.

use std::{fmt, str, str::FromStr};

use serde::{Deserialize, Serialize, de};
use thiserror::Error;

/// Invalid [`ThreemaId`].
#[derive(Debug, Error)]
pub enum ThreemaIdError {
    /// Invalid length (must be exactly 8 bytes).
    #[error("Threema ID must be exactly 8 bytes")]
    InvalidLength,

    /// Invalid symbols provided.
    #[error("Threema ID contains invalid symbols")]
    InvalidSymbols,
}

/// A valid Threema ID.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize)]
pub struct ThreemaId([u8; Self::LENGTH]);

impl ThreemaId {
    /// Byte length of a Threema ID.
    pub const LENGTH: usize = 8;

    /// Byte representation of the Threema ID.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// String representation of the Threema ID.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Unwrapping because creation of a `ThreemaId` requires that it is a valid UTF-8 sequence (ASCII
        // subset).
        str::from_utf8(&self.0).expect("ThreemaId is always valid UTF-8")
    }

    /// Return whether this is a Gateway ID.
    #[inline]
    #[must_use]
    pub fn is_gateway_id(self) -> bool {
        self.0[0] == b'*'
    }
}

impl fmt::Display for ThreemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for ThreemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ThreemaId").field(&self.to_string()).finish()
    }
}

impl From<ThreemaId> for String {
    fn from(id: ThreemaId) -> Self {
        id.as_str().to_owned()
    }
}

impl<'de> Deserialize<'de> for ThreemaId {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ThreemaIdVisitor;

        impl de::Visitor<'_> for ThreemaIdVisitor {
            type Value = ThreemaId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string of exactly 8 ASCII characters")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                ThreemaId::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ThreemaIdVisitor)
    }
}

impl TryFrom<&[u8]> for ThreemaId {
    type Error = ThreemaIdError;

    fn try_from(id: &[u8]) -> Result<Self, Self::Error> {
        let id = <[u8; Self::LENGTH]>::try_from(id).map_err(|_| ThreemaIdError::InvalidLength)?;

        // Valid characters: 0-9A-Z
        // Additionally, the first char may be a `*` (in case of Gateway IDs)
        let is_valid_char = |byte: &u8| matches!(byte, b'0'..=b'9' | b'A'..=b'Z');

        if !is_valid_char(&id[0]) && id[0] != b'*' {
            return Err(ThreemaIdError::InvalidSymbols);
        }
        if !id[1..].iter().all(is_valid_char) {
            return Err(ThreemaIdError::InvalidSymbols);
        }

        Ok(ThreemaId(id))
    }
}

impl TryFrom<&str> for ThreemaId {
    type Error = ThreemaIdError;

    fn try_from(id: &str) -> Result<Self, Self::Error> {
        Self::try_from(id.as_bytes())
    }
}

impl FromStr for ThreemaId {
    type Err = ThreemaIdError;

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Self::try_from(id)
    }
}

#[cfg(feature = "sqlx")]
impl<DB> sqlx::Type<DB> for ThreemaId
where
    DB: sqlx::Database,
    String: sqlx::Type<DB>,
{
    fn type_info() -> <DB as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<DB>>::type_info()
    }

    fn compatible(ty: &<DB as sqlx::Database>::TypeInfo) -> bool {
        <String as sqlx::Type<DB>>::compatible(ty)
    }
}

#[cfg(feature = "sqlx")]
impl<'enc, DB> sqlx::Encode<'enc, DB> for ThreemaId
where
    DB: sqlx::Database,
    String: sqlx::Encode<'enc, DB>,
{
    fn encode_by_ref(
        &self,
        buf: &mut <DB as sqlx::Database>::ArgumentBuffer<'enc>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<'enc, DB>>::encode(self.as_str().to_owned(), buf)
    }
}

#[cfg(feature = "sqlx")]
impl<'dec, DB> sqlx::Decode<'dec, DB> for ThreemaId
where
    DB: sqlx::Database,
    String: sqlx::Decode<'dec, DB>,
{
    fn decode(
        value: <DB as sqlx::Database>::ValueRef<'dec>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let decoded = <String as sqlx::Decode<'dec, DB>>::decode(value)?;
        ThreemaId::try_from(decoded.as_str()).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{ThreemaId, ThreemaIdError};

    #[rstest]
    #[case::alphanumeric("ECHOECHO")]
    #[case::gateway("*RICHTIG")]
    fn valid_from_str(#[case] input: &str) {
        assert!(ThreemaId::try_from(input).is_ok());
    }

    #[rstest]
    #[case::alphanumeric([0x45, 0x43, 0x48, 0x4f, 0x45, 0x43, 0x48, 0x4f])]
    #[case::gateway([0x2a, 0x52, 0x49, 0x43, 0x48, 0x54, 0x49, 0x47])]
    fn valid_from_bytes(#[case] input: [u8; 8]) {
        assert!(ThreemaId::try_from(input.as_slice()).is_ok());
    }

    #[rstest]
    #[case::empty("")]
    #[case::too_short("ZUWENIG")]
    #[case::too_long("*NEINNEIN")]
    #[case::non_ascii("ECHÜECHÜ")]
    fn invalid_length(#[case] input: &str) {
        assert!(matches!(
            ThreemaId::try_from(input),
            Err(ThreemaIdError::InvalidLength)
        ));
    }

    #[rstest]
    #[case::null_bytes([0x00, 0x9f, 0x92, 0x96, 0x00, 0x00, 0x00, 0x00])]
    #[case::all_zeroes([0_u8; 8])]
    fn invalid_symbols_from_bytes(#[case] input: [u8; 8]) {
        assert!(matches!(
            ThreemaId::try_from(input.as_slice()),
            Err(ThreemaIdError::InvalidSymbols)
        ));
    }

    #[rstest]
    #[case::underscores("ECH_ECH_")]
    #[case::all_stars("********")]
    fn invalid_symbols_from_str(#[case] input: &str) {
        assert!(matches!(
            ThreemaId::try_from(input),
            Err(ThreemaIdError::InvalidSymbols)
        ));
    }

    #[rstest]
    #[case::gateway("*RICHTIG", true)]
    #[case::alphanumeric("ECHOECHO", false)]
    fn is_gateway_id(#[case] input: &str, #[case] expected: bool) {
        let id = ThreemaId::try_from(input).unwrap();
        assert_eq!(id.is_gateway_id(), expected);
    }

    #[test]
    fn as_bytes() {
        let id = ThreemaId::try_from("ECHOECHO").unwrap();
        assert_eq!(id.as_bytes(), b"ECHOECHO");
    }

    #[test]
    fn display() {
        let id = ThreemaId::try_from("ECHOECHO").unwrap();
        assert_eq!(format!("{id}"), "ECHOECHO");
    }

    #[test]
    fn debug() {
        let id = ThreemaId::try_from("ECHOECHO").unwrap();
        assert_eq!(format!("{id:?}"), "ThreemaId(\"ECHOECHO\")");
    }

    #[test]
    fn into_string() {
        let id = ThreemaId::try_from("ECHOECHO").unwrap();
        assert_eq!(String::from(id), "ECHOECHO");
    }

    #[test]
    fn from_str() {
        let id: ThreemaId = "ECHOECHO".parse().unwrap();
        assert_eq!(id.as_str(), "ECHOECHO");
    }

    mod deserialize {
        use super::ThreemaId;

        /// Deserialize from borrowed `&str` (e.g. `serde_json::from_str`).
        #[test]
        fn from_borrowed_str() {
            let id: ThreemaId = serde_json::from_str("\"ECHOECHO\"").unwrap();
            assert_eq!(id.as_str(), "ECHOECHO");
        }

        /// Deserialize from owned `String` (e.g. `serde_json::from_value`).
        #[test]
        fn from_owned_string() {
            let value = serde_json::Value::String("ECHOECHO".to_owned());
            let id: ThreemaId = serde_json::from_value(value).unwrap();
            assert_eq!(id.as_str(), "ECHOECHO");
        }

        /// Trigger the `expecting` error message by passing a non-string value.
        #[test]
        fn from_non_string_fails() {
            let result: Result<ThreemaId, _> = serde_json::from_str("42");
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "sqlx")]
    mod sqlx_bounds {
        use super::ThreemaId;

        #[test]
        fn implements_sqlx_traits() {
            fn assert_type<T: sqlx::Type<sqlx::Sqlite>>() {}
            fn assert_encode<T: for<'enc> sqlx::Encode<'enc, sqlx::Sqlite>>() {}
            fn assert_decode<T: for<'dec> sqlx::Decode<'dec, sqlx::Sqlite>>() {}
            assert_type::<ThreemaId>();
            assert_encode::<ThreemaId>();
            assert_decode::<ThreemaId>();
        }
    }
}
