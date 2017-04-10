use std::convert::From;

use data_encoding::hex;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

use ::connection::{Recipient, send_simple};
use ::crypto::{encrypt, EncryptedMessage};
use ::errors::{ApiBuilderError, CryptoError, ApiError};
use ::lookup::{LookupCriterion, lookup_id, lookup_pubkey};

/// The public key of a recipient.
pub struct RecipientKey(pub PublicKey);

impl From<PublicKey> for RecipientKey {
    fn from(val: PublicKey) -> Self {
        RecipientKey(val)
    }
}

impl From<[u8; 32]> for RecipientKey {
    fn from(val: [u8; 32]) -> Self {
        RecipientKey(PublicKey(val))
    }
}

/// Implement methods available on both the simple and the e2e API objects.
macro_rules! impl_common_functionality {

    () => {
        /// Fetch the public key for the specified Threema ID.
        ///
        /// For the end-to-end encrypted mode, you need the public key of the recipient
        /// in order to encrypt a message. While it's best to obtain this directly from
        /// the recipient (extract it from the QR code), this may not be convenient,
        /// and therefore you can also look up the key associated with a given ID from
        /// the server.
        ///
        /// It is strongly recommended that you cache the public keys to avoid querying
        /// the API for each message.
        pub fn lookup_pubkey(&self, id: &str) -> Result<String, ApiError> {
            lookup_pubkey(&self.id, id, &self.secret)
        }

        /// Look up a Threema ID in the directory.
        /// 
        /// An ID can be looked up either by a phone number or an e-mail
        /// address, in plaintext or hashed form. You can specify one of those
        /// criteria using the [`LookupCriterion`](enum.LookupCriterion.html)
        /// enum.
        pub fn lookup_id(&self, criterion: &LookupCriterion) -> Result<String, ApiError> {
            lookup_id(criterion, &self.id, &self.secret)
        }
    }
}

impl RecipientKey {
    /// Create a `RecipientKey` from a byte slice. It must contain 32 bytes.
    pub fn from_bytes(val: &[u8]) -> Result<Self, CryptoError> {
        match PublicKey::from_slice(val) {
            Some(pk) => Ok(RecipientKey(pk)),
            None => Err(CryptoError::BadKey("Invalid libsodium public key".into())),
        }
    }

    /// Create a `RecipientKey` from a hex encoded string slice.
    pub fn from_str(val: &str) -> Result<Self, CryptoError> {
        // TODO: to_uppercase() allocates a new String. This is necessary because
        // hex decoding only accepts uppercase letters. Would be nice to get rid of
        // that.
        let bytes = hex::decode(val.to_uppercase().as_bytes())
            .map_err(|e| CryptoError::BadKey(format!("Could not decode public key hex string: {}", e)))?;
        RecipientKey::from_bytes(bytes.as_slice())
    }
}

/// Struct to talk to the simple API (without end-to-end encryption).
pub struct SimpleApi {
    id: String,
    secret: String,
}

impl SimpleApi {
    /// Initialize the simple API with the Gateway ID and the Gateway Secret.
    pub fn new<I: Into<String>, S: Into<String>>(id: I, secret: S) -> Self {
        return SimpleApi { id: id.into(), secret: secret.into() }
    }

    /// Send a message to the specified recipient in basic mode.
    ///
    /// Note that this mode of sending messages does not provide end-to-end
    /// encryption, only transport encryption between your host and the Threema
    /// Gateway server.
    pub fn send(&self, to: &Recipient, text: &str) -> Result<String, ApiError> {
        send_simple(&self.id, to, &self.secret, text)
    }

    impl_common_functionality!();
}

/// Struct to talk to the E2E API (with end-to-end encryption).
pub struct E2eApi {
    id: String,
    secret: String,
    private_key: SecretKey,
}

impl E2eApi {
    /// Initialize the simple API with the Gateway ID, the Gateway Secret and
    /// the Private Key.
    pub fn new<I: Into<String>, S: Into<String>>(id: I, secret: S, private_key: SecretKey) -> Self {
        return E2eApi {
            id: id.into(),
            secret: secret.into(),
            private_key: private_key,
        }
    }

    /// Encrypt a message for the specified recipient public key.
    pub fn encrypt(&self, data: &[u8], recipient_key: &RecipientKey) -> EncryptedMessage {
        encrypt(data, &recipient_key.0, &self.private_key)
    }

    impl_common_functionality!();
}

/// A convenient way to set up the API object.
/// 
/// # Examples
/// 
/// ## Simple API
/// 
/// ```
/// use threema_gateway::{ApiBuilder, SimpleApi};
/// 
/// let gateway_id = "*3MAGWID";
/// let gateway_secret = "hihghrg98h00ghrg";
/// 
/// let api: SimpleApi = ApiBuilder::new(gateway_id, gateway_secret).into_simple();
/// ```
/// 
/// ## E2E API
/// 
/// ```
/// use threema_gateway::{ApiBuilder, E2eApi};
/// 
/// let gateway_id = "*3MAGWID";
/// let gateway_secret = "hihghrg98h00ghrg";
/// let private_key = "998730fbcac1c57dbb181139de41d12835b3fae6af6acdf6ce91670262e88453";
/// 
/// let api: E2eApi = ApiBuilder::new(gateway_id, gateway_secret)
///                              .with_private_key_str(private_key)
///                              .and_then(|builder| builder.into_e2e())
///                              .unwrap();
/// ```
pub struct ApiBuilder {
    pub id: String,
    pub secret: String,
    pub private_key: Option<SecretKey>,
}

impl ApiBuilder {
    /// Initialize the ApiBuilder with the Gateway ID and the Gateway Secret.
    pub fn new<I: Into<String>, S: Into<String>>(id: I, secret: S) -> Self {
        ApiBuilder {
            id: id.into(),
            secret: secret.into(),
            private_key: None,
        }
    }

    /// Return a [`SimpleAPI`](struct.SimpleApi.html) instance.
    pub fn into_simple(self) -> SimpleApi {
        SimpleApi::new(self.id, self.secret)
    }

    /// Set the private key. Only needed for E2e mode.
    pub fn with_private_key(mut self, private_key: SecretKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Set the private key from a byte slice. Only needed for E2e mode.
    pub fn with_private_key_bytes(mut self, private_key: &[u8]) -> Result<Self, ApiBuilderError> {
        let private_key = SecretKey::from_slice(private_key)
            .ok_or(ApiBuilderError::InvalidKey("Invalid libsodium private key".into()))?;
        self.private_key = Some(private_key);
        Ok(self)
    }

    /// Set the private key from a hex-encoded string reference. Only needed
    /// for E2e mode.
    pub fn with_private_key_str(self, private_key: &str) -> Result<Self, ApiBuilderError> {
        // TODO: to_uppercase() allocates a new String. This is necessary because
        // hex decoding only accepts uppercase letters. Would be nice to get rid of
        // that.
        let private_key_bytes = hex::decode(private_key.to_uppercase().as_bytes())
            .map_err(|e| {
                let msg = format!("Could not decode private key hex string: {}", e);
                ApiBuilderError::InvalidKey(msg)
            })?;
        self.with_private_key_bytes(&private_key_bytes)
    }

    /// Return a [`E2eAPI`](struct.SimpleApi.html) instance.
    pub fn into_e2e(self) -> Result<E2eApi, ApiBuilderError> {
        match self.private_key {
            Some(key) => Ok(E2eApi::new(self.id, self.secret, key)),
            None => Err(ApiBuilderError::MissingKey),
        }
    }
}

#[cfg(test)]
mod test {
    use sodiumoxide::crypto::box_::PublicKey;

    use super::*;

    #[test]
    fn test_recipient_key_from_publickey() {
        let bytes = [0; 32];
        let key = PublicKey::from_slice(&bytes).unwrap();
        let recipient: RecipientKey = key.into();
    }

    #[test]
    fn test_recipient_key_from_arr() {
        let bytes = [0; 32];
        let recipient: RecipientKey = bytes.into();
    }

    #[test]
    fn test_recipient_key_from_bytes() {
        let bytes = [0; 32];
        let recipient = RecipientKey::from_bytes(&bytes);
        assert!(recipient.is_ok());

        let too_short = [0; 24];
        let recipient = RecipientKey::from_bytes(&too_short);
        assert!(recipient.is_err());
    }

    #[test]
    fn test_recipient_key_from_str() {
        let encoded = "5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0";
        let recipient = RecipientKey::from_str(&encoded);
        assert!(recipient.is_ok());

        let too_short = "5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5ca";
        let recipient = RecipientKey::from_str(&too_short);
        assert!(recipient.is_err());

        let invalid = "qyz143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0";
        let recipient = RecipientKey::from_str(&invalid);
        assert!(recipient.is_err());
    }
}
