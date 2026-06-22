//! Validated Threema ID wrapper.

use std::sync::Arc;

use threema_gateway as lib;

use crate::errors::ApiError;

/// A Threema ID.
///
/// Construction validates the input: once a `ThreemaId` exists, callers can pass it to API
/// methods without paying for re-validation at each call site.
#[derive(uniffi::Object)]
pub struct ThreemaId {
    pub(crate) inner: lib::ThreemaId,
}

#[uniffi::export]
impl ThreemaId {
    /// Parse a Threema ID from its string representation.
    ///
    /// A Threema ID is 8 ASCII characters from `[0-9A-Z]`, optionally prefixed with `*` for
    /// gateway IDs.
    ///
    /// Returns [`ApiError::InvalidThreemaId`] on wrong length or invalid characters.
    #[uniffi::constructor]
    pub(crate) fn new(value: &str) -> Result<Arc<Self>, ApiError> {
        Ok(Arc::new(Self {
            inner: value.parse()?,
        }))
    }

    /// String representation of this Threema ID (8 ASCII characters).
    pub(crate) fn as_str(&self) -> String {
        self.inner.as_str().to_owned()
    }

    /// Whether this is a gateway ID (starts with `*`).
    pub(crate) fn is_gateway_id(&self) -> bool {
        self.inner.is_gateway_id()
    }
}

impl From<lib::ThreemaId> for ThreemaId {
    fn from(inner: lib::ThreemaId) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod new {
        use super::*;

        #[test]
        fn valid() {
            let id = ThreemaId::new("ECHOECHO").expect("valid Threema ID");
            assert_eq!(id.as_str(), "ECHOECHO");
        }

        #[test]
        fn gateway() {
            let id = ThreemaId::new("*MYGATWY").expect("valid gateway ID");
            assert!(id.is_gateway_id());
        }

        #[test]
        fn too_short() {
            let result = ThreemaId::new("SHORT");
            assert!(matches!(result, Err(ApiError::InvalidThreemaId { .. })));
        }

        #[test]
        fn too_long() {
            let result = ThreemaId::new("MUCHTOOLONG");
            assert!(matches!(result, Err(ApiError::InvalidThreemaId { .. })));
        }

        #[test]
        fn invalid_chars() {
            let result = ThreemaId::new("echoecho");
            assert!(matches!(result, Err(ApiError::InvalidThreemaId { .. })));
        }
    }

    mod is_gateway_id {
        use super::*;

        #[test]
        fn true_for_gateway_prefix() {
            let id = ThreemaId::new("*MYGATWY").expect("valid");
            assert!(id.is_gateway_id());
        }

        #[test]
        fn false_for_regular_id() {
            let id = ThreemaId::new("ECHOECHO").expect("valid");
            assert!(!id.is_gateway_id());
        }
    }
}
