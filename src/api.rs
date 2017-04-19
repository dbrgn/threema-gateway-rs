use std::collections::HashMap;
use std::convert::{From, Into};
use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

use ::connection::{BlobId, Recipient, send_e2e, send_simple, blob_upload};
use ::crypto::{encrypt, encrypt_raw, EncryptedMessage, MessageType};
use ::errors::{ApiBuilderError, CryptoError, ApiError};
use ::lookup::{LookupCriterion, Capabilities};
use ::lookup::{lookup_id, lookup_pubkey, lookup_capabilities, lookup_credits};

/// The public key of a recipient.
pub struct RecipientKey(pub PublicKey);

impl From<PublicKey> for RecipientKey {
    /// Create a `RecipientKey` from a `PublicKey` instance.
    fn from(val: PublicKey) -> Self {
        RecipientKey(val)
    }
}

impl From<[u8; 32]> for RecipientKey {
    /// Create a `RecipientKey` from a byte array
    fn from(val: [u8; 32]) -> Self {
        RecipientKey(PublicKey(val))
    }
}

impl Into<String> for RecipientKey {
    /// Encode the key bytes as lowercase hex string.
    fn into(self) -> String {
        HEXLOWER.encode(&(self.0).0)
    }
}

impl RecipientKey {
    /// Return a reference to the contained key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &(self.0).0
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

        /// Look up the capabilities of a certain Threema ID.
        ///
        /// Before you send a file to a Threema ID using the blob upload (+file
        /// message), you may want to check whether the recipient uses a
        /// Threema version that supports receiving files. The receiver may be
        /// using an old version, or a platform where file reception is not
        /// supported.
        pub fn lookup_capabilities(&self, id: &str) -> Result<Capabilities, ApiError> {
            lookup_capabilities(&self.id, id, &self.secret)
        }

        /// Look up a remaining gateway credits.
        pub fn lookup_credits(&self) -> Result<i64, ApiError> {
            lookup_credits(&self.id, &self.secret)
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
        let bytes = HEXLOWER_PERMISSIVE.decode(val.as_bytes())
            .map_err(|e| CryptoError::BadKey(format!("Could not decode public key hex string: {}", e)))?;
        RecipientKey::from_bytes(bytes.as_slice())
    }
}

/// Struct to talk to the simple API (without end-to-end encryption).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    ///
    /// Cost: 1 credit.
    pub fn send(&self, to: &Recipient, text: &str) -> Result<String, ApiError> {
        send_simple(&self.id, to, &self.secret, text)
    }

    impl_common_functionality!();
}

/// Struct to talk to the E2E API (with end-to-end encryption).
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Encrypt raw bytes for the specified recipient public key.
    pub fn encrypt_raw(&self, data: &[u8], recipient_key: &RecipientKey) -> EncryptedMessage {
        encrypt_raw(data, &recipient_key.0, &self.private_key)
    }

    /// Encrypt a text message for the specified recipient public key.
    pub fn encrypt_text(&self, text: &str, recipient_key: &RecipientKey) -> EncryptedMessage {
        let data = text.as_bytes();
        let msgtype = MessageType::Text;
        encrypt(data, msgtype, &recipient_key.0, &self.private_key)
    }

    /// Encrypt an image message for the specified recipient public key.
    ///
    /// Before calling this function, you need to encrypt the image data (JPEG
    /// format) with [`encrypt_raw`](struct.E2eApi.html#method.encrypt_raw) and
    /// upload the ciphertext to the blob server.
    ///
    /// The image size needs to be specified in bytes. Note that the size is
    /// only used for download size displaying purposes and has no security
    /// implications.
    pub fn encrypt_image(&self,
                         blob_id: &BlobId,
                         img_size_bytes: u32,
                         image_data_nonce: &[u8; 24],
                         recipient_key: &RecipientKey)
                         -> EncryptedMessage {
        let mut data = [0; 44];
        // Since we're writing to an array and not to a file or socket, these
        // write operations should never fail.
        (&mut data[0..16]).write_all(&blob_id.0).expect("Writing to buffer failed");
        (&mut data[16..20]).write_u32::<LittleEndian>(img_size_bytes).expect("Writing to buffer failed");
        (&mut data[20..44]).write_all(image_data_nonce).expect("Writing to buffer failed");
        let msgtype = MessageType::Image;
        encrypt(&data, msgtype, &recipient_key.0, &self.private_key)
    }

    /// Send an encrypted E2E message to the specified Threema ID.
    ///
    /// Cost: 1 credit.
    pub fn send(&self, to: &str, message: &EncryptedMessage) -> Result<String, ApiError> {
        send_e2e(&self.id, to, &self.secret, &message.nonce, &message.ciphertext, None)
    }

    /// Used for testing purposes. Not intended to be called by end users.
    #[doc(hidden)]
    pub fn send_with_params(&self,
                            to: &str,
                            message: &EncryptedMessage,
                            additional_params: HashMap<String, String>)
                            -> Result<String, ApiError> {
        send_e2e(&self.id, to, &self.secret, &message.nonce, &message.ciphertext, Some(additional_params))
    }

    impl_common_functionality!();

    /// Upload encrypted data to the blob server.
    ///
    /// Cost: 1 credit.
    pub fn blob_upload(&self, data: &EncryptedMessage) -> Result<BlobId, ApiError> {
        blob_upload(&self.id, &self.secret, data)
    }
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
#[derive(Debug)]
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
        let private_key_bytes = HEXLOWER_PERMISSIVE.decode(private_key.as_bytes())
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
    use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey, Nonce};

    use super::*;
    use ::connection::BlobId;
    use ::crypto::MessageType;

    #[test]
    fn test_recipient_key_from_publickey() {
        let bytes = [0; 32];
        let key = PublicKey::from_slice(&bytes).unwrap();
        let _: RecipientKey = key.into();
    }

    #[test]
    fn test_recipient_key_from_arr() {
        let bytes = [0; 32];
        let _: RecipientKey = bytes.into();
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

        let encoded = "5CF143CD8F3652F31D9B44786C323FBC222ECFCBB8DAC5CAF5CAA257AC272DF0";
        let recipient = RecipientKey::from_str(&encoded);
        assert!(recipient.is_ok());

        let too_short = "5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5ca";
        let recipient = RecipientKey::from_str(&too_short);
        assert!(recipient.is_err());

        let invalid = "qyz143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0";
        let recipient = RecipientKey::from_str(&invalid);
        assert!(recipient.is_err());
    }

    #[test]
    fn test_recipient_key_as_bytes() {
        let bytes = [0; 32];
        let recipient = RecipientKey::from_bytes(&bytes).unwrap();
        let bytes_ref = recipient.as_bytes();
        for i in 0..31 {
            assert_eq!(bytes[i], bytes_ref[i]);
        }
    }

    #[test]
    fn test_recipient_key_as_string() {
        let mut bytes = [0; 32];
        bytes[0] = 0xff;
        bytes[31] = 0xee;
        let recipient = RecipientKey::from_bytes(&bytes).unwrap();
        let string: String = recipient.into();
        assert_eq!(string, "ff000000000000000000000000000000000000000000000000000000000000ee");
    }

    #[test]
    fn test_encrypt_image() {
        // Set up keys
        let own_sec = SecretKey([113,146,154,1,241,143,18,181,240,174,72,16,247,83,161,29,215,123,130,243,235,222,137,151,107,162,47,119,98,145,68,146]);
        let other_pub = PublicKey([153,153,204,118,225,119,78,112,88,6,167,2,67,73,254,255,96,134,225,8,36,229,124,219,43,50,241,185,244,236,55,77]);

        // Set up API
        let api = E2eApi::new("*3MAGWID", "1234", own_sec.clone());

        // Fake a blob upload
        let blob_id = BlobId::from_str("00112233445566778899aabbccddeeff").unwrap();
        let blob_nonce = box_::gen_nonce();

        // Encrypt
        let recipient_key = RecipientKey(other_pub.clone());
        let encrypted = api.encrypt_image(&blob_id, 258, &blob_nonce.0, &recipient_key);

        // Decrypt
        let decrypted = box_::open(&encrypted.ciphertext, &Nonce(encrypted.nonce), &other_pub, &own_sec).unwrap();

        // Validate and remove padding
        let padding_bytes = decrypted[decrypted.len()-1] as usize;
        assert!(
            decrypted[decrypted.len()-padding_bytes..decrypted.len()]
                .iter().all(|b| *b == padding_bytes as u8)
        );
        let data: &[u8] = &decrypted[0..decrypted.len()-padding_bytes];

        // Validate message type
        let msgtype: u8 = MessageType::Image.into();
        assert_eq!(data[0], msgtype);
        assert_eq!(data.len(), 44 + 1);
        assert_eq!(&data[1..17], &blob_id.0);
        assert_eq!(&data[17..21], &[2, 1, 0, 0]);
        assert_eq!(&data[21..45], &blob_nonce.0);
    }
}
