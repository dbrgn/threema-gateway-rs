//! Encrypt and decrypt messages.

use std::convert::Into;
use std::io::Write;
use std::iter::repeat;
use std::str::FromStr;
use std::string::ToString;

use byteorder::{LittleEndian, WriteBytesExt};
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use serde_json as json;
use sodiumoxide::crypto::box_;
use sodiumoxide::randombytes::randombytes_into;

use crate::errors::CryptoError;
use crate::types::{BlobId, FileMessage, MessageType, RenderingType};
use crate::{Key, Mime, PublicKey, SecretKey};

/// Return a random number in the range `[1, 255]`.
fn random_padding_amount() -> u8 {
    let mut buf: [u8; 1] = [0];
    loop {
        randombytes_into(&mut buf);
        if buf[0] < 255 {
            return buf[0] + 1;
        }
    }
}

/// An encrypted message. Contains both the ciphertext and the nonce.
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
}

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
    /// Create a `RecipientKey` from a byte slice. It must contain 32 bytes.
    pub fn from_bytes(val: &[u8]) -> Result<Self, CryptoError> {
        match PublicKey::from_slice(val) {
            Some(pk) => Ok(RecipientKey(pk)),
            None => Err(CryptoError::BadKey("Invalid libsodium public key".into())),
        }
    }

    /// Return a reference to the contained key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &(self.0).0
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

/// Encrypt data for the recipient.
pub fn encrypt_raw(
    data: &[u8],
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> EncryptedMessage {
    sodiumoxide::init().expect("Could not initialize sodiumoxide library.");
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&data, &nonce, public_key, private_key);
    EncryptedMessage {
        ciphertext,
        nonce: nonce.0,
    }
}

/// Encrypt a message for the recipient.
pub fn encrypt(
    data: &[u8],
    msgtype: MessageType,
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> EncryptedMessage {
    // Add random amount of PKCS#7 style padding
    let padding_amount = random_padding_amount();
    let padding = repeat(padding_amount).take(padding_amount as usize);
    let msgtype_byte = repeat(msgtype.into()).take(1);
    let padded_plaintext: Vec<u8> = msgtype_byte
        .chain(data.iter().cloned())
        .chain(padding)
        .collect();

    // Encrypt
    encrypt_raw(&padded_plaintext, &public_key, &private_key)
}

/// Encrypt an image message for the recipient.
pub fn encrypt_image_msg(
    blob_id: &BlobId,
    img_size_bytes: u32,
    image_data_nonce: &[u8; 24],
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> EncryptedMessage {
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
    file_blob_id: &BlobId,
    thumbnail_blob_id: Option<&BlobId>,
    blob_encryption_key: &Key,
    mime_type: &Mime,
    file_name: Option<&str>,
    file_size_bytes: u32,
    description: Option<&str>,
    rendering_type: RenderingType,
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> EncryptedMessage {
    let msg = FileMessage::new(
        file_blob_id.clone(),
        thumbnail_blob_id.cloned(),
        blob_encryption_key.clone(),
        mime_type.clone(),
        file_name.map(ToString::to_string),
        file_size_bytes,
        description.map(ToString::to_string),
        rendering_type,
    );
    let data = json::to_string(&msg).unwrap();
    let msgtype = MessageType::File;
    encrypt(&data.as_bytes(), msgtype, &public_key, &private_key)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use crate::api::ApiBuilder;
    use crate::types::{BlobId, MessageType};
    use sodiumoxide::crypto::box_::{self, Nonce, PublicKey, SecretKey};

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
        let own_sec = SecretKey([
            113, 146, 154, 1, 241, 143, 18, 181, 240, 174, 72, 16, 247, 83, 161, 29, 215, 123, 130,
            243, 235, 222, 137, 151, 107, 162, 47, 119, 98, 145, 68, 146,
        ]);
        let other_pub = PublicKey([
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
        let blob_nonce = box_::gen_nonce();

        // Encrypt
        let recipient_key = RecipientKey(other_pub);
        let encrypted = api.encrypt_image_msg(&blob_id, 258, &blob_nonce.0, &recipient_key);

        // Decrypt
        let decrypted = box_::open(
            &encrypted.ciphertext,
            &Nonce(encrypted.nonce),
            &other_pub,
            &own_sec,
        )
        .unwrap();

        // Validate and remove padding
        let padding_bytes = decrypted[decrypted.len() - 1] as usize;
        assert!(decrypted[decrypted.len() - padding_bytes..decrypted.len()]
            .iter()
            .all(|b| *b == padding_bytes as u8));
        let data: &[u8] = &decrypted[0..decrypted.len() - padding_bytes];

        // Validate message type
        let msgtype: u8 = MessageType::Image.into();
        assert_eq!(data[0], msgtype);
        assert_eq!(data.len(), 44 + 1);
        assert_eq!(&data[1..17], &blob_id.0);
        assert_eq!(&data[17..21], &[2, 1, 0, 0]);
        assert_eq!(&data[21..45], &blob_nonce.0);
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
        assert_eq!(
            string,
            "ff000000000000000000000000000000000000000000000000000000000000ee"
        );
    }
}
