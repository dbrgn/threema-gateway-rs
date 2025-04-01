//! Encrypt and decrypt messages.

use std::{convert::Into, fmt::Debug, io::Write, iter::repeat, str::FromStr, sync::OnceLock};

use byteorder::{LittleEndian, WriteBytesExt};
use crypto_box::{SalsaBox, aead::Aead};
use crypto_secretbox::{
    AeadCore, Key as SecretboxKey, KeyInit, Nonce, XSalsa20Poly1305,
    aead::{OsRng, Payload},
    cipher::generic_array::GenericArray,
};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use rand::Rng;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json as json;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    PublicKey, SecretKey,
    errors::{self, CryptoError},
    types::{BlobId, FileMessage, MessageType},
};

pub const NONCE_SIZE: usize = 24;
const KEY_SIZE: usize = 32;

/// Key type used for nacl secretbox cryptography
#[derive(PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Key(SecretboxKey);

impl AsRef<SecretboxKey> for Key {
    fn as_ref(&self) -> &SecretboxKey {
        &self.0
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write! {f, "Key([…])"}
    }
}

impl From<SecretboxKey> for Key {
    fn from(value: SecretboxKey) -> Self {
        Self(value)
    }
}

impl From<[u8; KEY_SIZE]> for Key {
    fn from(value: [u8; KEY_SIZE]) -> Self {
        Self(GenericArray::from(value))
    }
}

impl TryFrom<Vec<u8>> for Key {
    type Error = errors::CryptoError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; KEY_SIZE]>::try_from(value)
            .map_err(|original| {
                CryptoError::BadKey(format!(
                    "Key has wrong size: {} instead of {}",
                    original.len(),
                    KEY_SIZE
                ))
            })
            .map(SecretboxKey::from)
            .map(Self::from)
    }
}

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&HEXLOWER.encode(&self.0))
    }
}

fn get_file_nonce() -> &'static Nonce {
    static FILE_NONCE: OnceLock<Nonce> = OnceLock::new();
    FILE_NONCE.get_or_init(|| {
        Nonce::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])
    })
}

fn get_thumb_nonce() -> &'static Nonce {
    static THUMB_NONCE: OnceLock<Nonce> = OnceLock::new();
    THUMB_NONCE.get_or_init(|| {
        Nonce::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ])
    })
}

/// Return a random number in the range `[1, 255]`.
fn random_padding_amount() -> u8 {
    let mut rng = rand::rng();
    rng.random_range(1..=255)
}

/// An encrypted message. Contains both the ciphertext and the nonce.
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: Nonce,
}

/// The public key of a recipient.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecipientKey(pub PublicKey);

impl<'de> Deserialize<'de> for RecipientKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl From<PublicKey> for RecipientKey {
    /// Create a `RecipientKey` from a `PublicKey` instance.
    fn from(val: PublicKey) -> Self {
        RecipientKey(val)
    }
}

impl From<[u8; 32]> for RecipientKey {
    /// Create a `RecipientKey` from a byte array
    fn from(val: [u8; 32]) -> Self {
        RecipientKey(PublicKey::from(val))
    }
}

impl RecipientKey {
    /// Create a `RecipientKey` from a byte slice. It must contain 32 bytes.
    pub fn from_bytes(val: &[u8]) -> Result<Self, CryptoError> {
        PublicKey::from_slice(val)
            .map(RecipientKey::from)
            .map_err(|_| CryptoError::BadKey("Invalid public key".into()))
    }

    /// Return a reference to the contained key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Encode the key bytes as lowercase hex string.
    pub fn to_hex_string(&self) -> String {
        HEXLOWER.encode(self.as_bytes())
    }
}

impl FromStr for RecipientKey {
    type Err = CryptoError;

    /// Create a `RecipientKey` from a hex encoded string slice.
    fn from_str(val: &str) -> Result<Self, Self::Err> {
        let bytes = HEXLOWER_PERMISSIVE.decode(val.as_bytes()).map_err(|e| {
            CryptoError::BadKey(format!("Could not decode public key hex string: {}", e))
        })?;
        RecipientKey::from_bytes(bytes.as_slice())
    }
}

/// Encrypt raw data for the recipient.
pub fn encrypt_raw(
    data: &[u8],
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> Result<EncryptedMessage, CryptoError> {
    let crypto_box: SalsaBox = SalsaBox::new(public_key, private_key);
    let nonce: Nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ciphertext = crypto_box
        .encrypt(&nonce, data)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(EncryptedMessage { ciphertext, nonce })
}

/// Encrypt a message with the specified `msgtype` for the recipient.
///
/// The encrypted data will include PKCS#7 style random padding.
pub fn encrypt(
    data: &[u8],
    msgtype: MessageType,
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> Result<EncryptedMessage, CryptoError> {
    // Add random amount of PKCS#7 style padding
    let padding_amount = random_padding_amount();
    let padding = repeat(padding_amount).take(padding_amount as usize);
    let msgtype_byte = repeat(msgtype.into()).take(1);
    let padded_plaintext: Vec<u8> = msgtype_byte
        .chain(data.iter().cloned())
        .chain(padding)
        .collect();

    // Encrypt
    encrypt_raw(&padded_plaintext, public_key, private_key)
}

/// Encrypt an image message for the recipient.
pub fn encrypt_image_msg(
    blob_id: &BlobId,
    img_size_bytes: u32,
    image_data_nonce: &Nonce,
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> Result<EncryptedMessage, CryptoError> {
    let mut data = [0; 44];
    // Since we're writing to an array and not to a file or socket, these
    // write operations should never fail.
    (&mut data[0..16])
        .write_all(&blob_id.0)
        .expect("Writing to buffer failed");
    (&mut data[16..20])
        .write_u32::<LittleEndian>(img_size_bytes)
        .expect("Writing to buffer failed");
    (&mut data[20..44])
        .write_all(image_data_nonce)
        .expect("Writing to buffer failed");
    let msgtype = MessageType::Image;
    encrypt(&data, msgtype, public_key, private_key)
}

/// Encrypt a file message for the recipient.
pub fn encrypt_file_msg(
    msg: &FileMessage,
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> Result<EncryptedMessage, CryptoError> {
    let data = json::to_string(msg).unwrap();
    let msgtype = MessageType::File;
    encrypt(data.as_bytes(), msgtype, public_key, private_key)
}

/// Raw unencrypted bytes of a file and optionally a thumbnail.
///
/// This struct is used as a parameter type for [`encrypt_file_data`] and
/// returned by [`decrypt_file_data`].
#[derive(Clone)]
pub struct FileData {
    pub file: Vec<u8>,
    pub thumbnail: Option<Vec<u8>>,
}

/// Encrypted bytes of a file and optionally a thumbnail.
///
/// This struct is used as a parameter type for [`decrypt_file_data`] and
/// returned by [`encrypt_file_data`].
#[derive(Clone)]
pub struct EncryptedFileData {
    pub file: Vec<u8>,
    pub thumbnail: Option<Vec<u8>>,
}

/// Encrypt file data and an optional thumbnail using a randomly generated
/// symmetric key.
///
/// Return the encrypted bytes and the key.
pub fn encrypt_file_data(data: &FileData) -> Result<(EncryptedFileData, Key), CryptoError> {
    // Generate a random encryption key
    let key: Key = XSalsa20Poly1305::generate_key(&mut OsRng).into();
    let secretbox = XSalsa20Poly1305::new(key.as_ref());

    // Encrypt data
    // Note: Since we generate a random key, we can safely re-use constant nonces.
    let file = secretbox
        .encrypt(get_file_nonce(), Payload::from(data.file.as_ref()))
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let thumbnail = data
        .thumbnail
        .as_ref()
        .map(|bytes| secretbox.encrypt(get_thumb_nonce(), Payload::from(bytes.as_ref())))
        .transpose()
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok((EncryptedFileData { file, thumbnail }, key))
}

/// Decrypt file data and optional thumbnail data with the provided symmetric
/// key.
///
/// Return the decrypted bytes.
pub fn decrypt_file_data(
    data: &EncryptedFileData,
    encryption_key: &Key,
) -> Result<FileData, CryptoError> {
    let secretbox = XSalsa20Poly1305::new(encryption_key.as_ref());

    let file = secretbox
        .decrypt(get_file_nonce(), Payload::from(data.file.as_ref()))
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let thumbnail = data
        .thumbnail
        .as_ref()
        .map(|bytes| secretbox.decrypt(get_thumb_nonce(), Payload::from(bytes.as_ref())))
        .transpose()
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(FileData { file, thumbnail })
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::{
        api::ApiBuilder,
        types::{BlobId, MessageType},
    };
    use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};

    use super::*;

    #[test]
    fn test_randombytes_uniform() {
        for _ in 0..500 {
            let random = random_padding_amount();
            assert!(random >= 1);
        }
    }

    #[test]
    /// Make sure that not all random numbers are the same.
    fn test_randombytes_uniform_not_stuck() {
        let random_numbers = (1..100)
            .map(|_| random_padding_amount())
            .collect::<Vec<u8>>();
        let first = random_numbers[0];
        assert!(!random_numbers.iter().all(|n| *n == first));
    }

    #[test]
    fn test_encrypt_image_msg() {
        // Set up keys
        let own_sec = SecretKey::from([
            113, 146, 154, 1, 241, 143, 18, 181, 240, 174, 72, 16, 247, 83, 161, 29, 215, 123, 130,
            243, 235, 222, 137, 151, 107, 162, 47, 119, 98, 145, 68, 146,
        ]);
        let other_pub = PublicKey::from([
            153, 153, 204, 118, 225, 119, 78, 112, 88, 6, 167, 2, 67, 73, 254, 255, 96, 134, 225,
            8, 36, 229, 124, 219, 43, 50, 241, 185, 244, 236, 55, 77,
        ]);

        // Set up API
        let api = ApiBuilder::new("*3MAGWID", "1234")
            .with_private_key(own_sec.clone())
            .into_e2e()
            .unwrap();

        // Fake a blob upload
        let blob_id = BlobId::from_str("00112233445566778899aabbccddeeff").unwrap();
        let blob_nonce: Nonce = SalsaBox::generate_nonce(&mut OsRng);

        // Encrypt
        let recipient_key = RecipientKey(other_pub);
        let encrypted = api
            .encrypt_image_msg(&blob_id, 258, &blob_nonce, &recipient_key)
            .unwrap();

        let crypto_box: SalsaBox = SalsaBox::new(&recipient_key.0, &own_sec);

        // Decrypt
        let decrypted = crypto_box
            .decrypt(
                &encrypted.nonce,
                Payload::from(encrypted.ciphertext.as_ref()),
            )
            .unwrap();

        // Validate and remove padding
        let padding_bytes = decrypted[decrypted.len() - 1] as usize;
        assert!(
            decrypted[decrypted.len() - padding_bytes..decrypted.len()]
                .iter()
                .all(|b| *b == padding_bytes as u8)
        );
        let data: &[u8] = &decrypted[0..decrypted.len() - padding_bytes];

        // Validate message type
        let msgtype: u8 = MessageType::Image.into();
        assert_eq!(data[0], msgtype);
        assert_eq!(data.len(), 44 + 1);
        assert_eq!(&data[1..17], &blob_id.0);
        assert_eq!(&data[17..21], &[2, 1, 0, 0]);
        assert_eq!(&data[21..45], &blob_nonce[..]);
    }

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
        let recipient = RecipientKey::from_str(encoded);
        assert!(recipient.is_ok());

        let encoded = "5CF143CD8F3652F31D9B44786C323FBC222ECFCBB8DAC5CAF5CAA257AC272DF0";
        let recipient = RecipientKey::from_str(encoded);
        assert!(recipient.is_ok());

        let too_short = "5cf143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5ca";
        let recipient = RecipientKey::from_str(too_short);
        assert!(recipient.is_err());

        let invalid = "qyz143cd8f3652f31d9b44786c323fbc222ecfcbb8dac5caf5caa257ac272df0";
        let recipient = RecipientKey::from_str(invalid);
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
        assert_eq!(
            recipient.to_hex_string(),
            "ff000000000000000000000000000000000000000000000000000000000000ee"
        );
    }

    #[test]
    fn test_encrypt_file_data() {
        let file_data = [1, 2, 3, 4];
        let thumb_data = [5, 6, 7];
        let data = FileData {
            file: file_data.to_vec(),
            thumbnail: Some(thumb_data.to_vec()),
        };

        // Encrypt
        let (encrypted, key) = encrypt_file_data(&data).unwrap();
        let encrypted_thumb = encrypted.thumbnail.expect("Thumbnail missing");

        let secretbox = XSalsa20Poly1305::new(key.as_ref());

        // Ensure that encrypted data is different from plaintext data
        assert_ne!(encrypted.file, file_data);
        assert_ne!(encrypted_thumb, thumb_data);

        // Test that data can be decrypted
        let decrypted_file = secretbox
            .decrypt(get_file_nonce(), Payload::from(encrypted.file.as_ref()))
            .unwrap();
        let decrypted_thumb = secretbox
            .decrypt(get_thumb_nonce(), Payload::from(encrypted_thumb.as_ref()))
            .unwrap();
        assert_eq!(decrypted_file, &file_data);
        assert_eq!(decrypted_thumb, &thumb_data);
    }

    #[test]
    fn test_encrypt_file_data_random_key() {
        // Ensure that a different key is generated each time
        let (_, key1) = encrypt_file_data(&FileData {
            file: [1, 2, 3].to_vec(),
            thumbnail: None,
        })
        .unwrap();
        let (_, key2) = encrypt_file_data(&FileData {
            file: [1, 2, 3].to_vec(),
            thumbnail: None,
        })
        .unwrap();
        let (_, key3) = encrypt_file_data(&FileData {
            file: [1, 2, 3].to_vec(),
            thumbnail: None,
        })
        .unwrap();
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_decrypt_file_data() {
        let file_data = [1, 2, 3, 4];
        let thumb_data = [5, 6, 7];
        let data = FileData {
            file: file_data.to_vec(),
            thumbnail: Some(thumb_data.to_vec()),
        };

        // Encrypt
        let (encrypted, key) = encrypt_file_data(&data).unwrap();
        assert_ne!(encrypted.file, data.file);
        assert!(encrypted.thumbnail.is_some());
        assert_ne!(encrypted.thumbnail, data.thumbnail);

        // Decrypt
        let decrypted = decrypt_file_data(&encrypted, &key).unwrap();
        assert_eq!(decrypted.file, &file_data);
        assert_eq!(decrypted.thumbnail.unwrap(), &thumb_data);
    }
}
