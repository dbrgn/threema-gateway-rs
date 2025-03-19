//! Code related to incoming messages received from Threema Gateway.

use std::{borrow::Cow, collections::HashMap};

use crypto_box::{PublicKey, SalsaBox, SecretKey, aead::Aead};
use crypto_secretbox::{Nonce, aead::Payload};
use data_encoding::HEXLOWER_PERMISSIVE;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer};
use sha2::Sha256;

use crate::{
    crypto::NONCE_SIZE,
    errors::{ApiError, CryptoError},
};

type HmacSha256 = Hmac<Sha256>;

/// Deserialize a hex string into a byte vector.
fn deserialize_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: &[u8] = Deserialize::deserialize(deserializer)?;
    HEXLOWER_PERMISSIVE
        .decode(bytes)
        .map_err(serde::de::Error::custom)
}

/// An incoming message received from Threema Gateway.
///
/// To receive the message, you'll need to provide your own HTTP callback
/// server implementation. The request body bytes that are received this way
/// can then be parsed using [`IncomingMessage::from_urlencoded_bytes`].
///
/// Note: The [`IncomingMessage::from_urlencoded_bytes`] function validates the
/// MAC, that's why it's not included in here again.
///
/// Further docs:
///
/// - API docs: <https://gateway.threema.ch/de/developer/api>
/// - E2E message format docs: <https://gateway.threema.ch/de/developer/e2e>
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IncomingMessage {
    /// Sender identity (8 characters)
    pub from: String,
    /// Your API identity (8 characters, usually starts with '*')
    pub to: String,
    /// Message ID assigned by the sender (8 bytes, hex encoded)
    pub message_id: String,
    /// Message date set by the sender (UNIX timestamp)
    pub date: usize,
    /// Nonce used for encryption (24 bytes, hex encoded)
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub nonce: Vec<u8>,
    /// Encrypted message data (max. 4000 bytes, hex encoded)
    #[serde(rename = "box")]
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub box_data: Vec<u8>,
    /// Public nickname of the sender, if set
    pub nickname: Option<String>,
}

impl IncomingMessage {
    /// Deserialize an incoming Threema Gateway message in
    /// `application/x-www-form-urlencoded` format.
    ///
    /// This will validate the MAC. If the MAC is invalid,
    /// [`ApiError::InvalidMac`] will be returned.
    ///
    /// Note: You should probably not use this directly, but instead use
    /// [`E2eApi::decode_incoming_message`](crate::E2eApi::decode_incoming_message)!
    pub fn from_urlencoded_bytes(
        bytes: impl AsRef<[u8]>,
        api_secret: &str,
    ) -> Result<Self, ApiError> {
        let bytes = bytes.as_ref();

        // Unfortunately we need to parse the urlencoding twice, first to
        // validate the MAC, then to deserialize the data.
        let values: HashMap<Cow<str>, Cow<str>> = form_urlencoded::parse(bytes).collect();

        // Decode MAC
        let mac_hex_bytes = values
            .get("mac")
            .ok_or_else(|| ApiError::ParseError("Missing request body field: mac".to_string()))?
            .as_bytes();

        if mac_hex_bytes.len() != 32 * 2 {
            return Err(ApiError::ParseError(format!(
                "Invalid MAC: Encoded length must be 64 hex characters, but is {} characters",
                mac_hex_bytes.len(),
            )));
        }

        let mut mac = [0u8; 32];
        let bytes_decoded = HEXLOWER_PERMISSIVE
            .decode_mut(mac_hex_bytes, &mut mac)
            .map_err(|_| ApiError::ParseError("Invalid hex bytes for MAC".to_string()))?;
        if bytes_decoded != 32 {
            return Err(ApiError::ParseError(format!(
                "Invalid MAC: Length must be 32 bytes, but is {} bytes",
                bytes_decoded
            )));
        }

        // Validate MAC
        let mut hmac_state = HmacSha256::new_from_slice(api_secret.as_bytes())
            .map_err(|_| ApiError::Other("Invalid api_secret".to_string()))?;
        for field in &["from", "to", "messageId", "date", "nonce", "box"] {
            hmac_state.update(
                values
                    .get(*field)
                    .ok_or_else(|| {
                        ApiError::ParseError(format!("Missing request body field: {}", field))
                    })?
                    .as_bytes(),
            );
        }

        if hmac_state.verify_slice(&mac).is_err() {
            return Err(ApiError::InvalidMac);
        }

        // MAC is valid, we can now deserialize
        serde_urlencoded::from_bytes(bytes)
            .map_err(|e| ApiError::ParseError(format!("Could not parse message: {}", e)))
    }

    /// Decrypt the box using the specified keys and remove padding.
    ///
    /// The public key belongs to the sender in the `from` field. The private
    /// key belongs to the gateway ID in the `to` field.
    ///
    /// The PKCS#7 padding will be removed. If the padding is missing or
    /// invalid, an [`CryptoError::BadPadding`] will be returned.
    ///
    /// Note: For more convenience, you might want to prefer the shortcut
    /// [`E2eApi::decrypt_incoming_message`](crate::E2eApi::decrypt_incoming_message)!
    pub fn decrypt_box(
        &self,
        public_key: &PublicKey,
        private_key: &SecretKey,
    ) -> Result<Vec<u8>, CryptoError> {
        // Decode nonce
        let nonce_bytes =
            <[u8; NONCE_SIZE]>::try_from(&self.nonce[..]).map_err(|_| CryptoError::BadNonce)?;
        let nonce: Nonce = Nonce::from(nonce_bytes);

        // Decrypt bytes
        let crypto_box: SalsaBox = SalsaBox::new(public_key, private_key);
        let mut decrypted = crypto_box
            .decrypt(&nonce, Payload::from(self.box_data.as_ref()))
            .map_err(|_| CryptoError::DecryptionFailed)?;

        // Remove PKCS#7 style padding
        let padding_amount = decrypted.last().cloned().ok_or(CryptoError::BadPadding)? as usize;
        if padding_amount >= decrypted.len() {
            return Err(CryptoError::BadPadding);
        }
        decrypted.resize(decrypted.len() - padding_amount, 0);

        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod incoming_message_deserialize {
        use super::*;

        const TEST_PAYLOAD: &[u8] = b"from=ECHOECHO&to=*TESTTST&messageId=0102030405060708&date=1616950936&nonce=ffffffffffffffffffffffffffffffffffffffffffffffff&box=012345abcdef&mac=622b362e8353658ee649a5548acecc9ce9b88384d6b7e08e212446d68455b14e";
        const TEST_MAC_SECRET: &str = "nevergonnagiveyouup";

        #[test]
        fn success() {
            let msg =
                IncomingMessage::from_urlencoded_bytes(TEST_PAYLOAD, TEST_MAC_SECRET).unwrap();
            assert_eq!(msg.from, "ECHOECHO");
            assert_eq!(msg.to, "*TESTTST");
            assert_eq!(msg.nonce, vec![0xff; 24]);
            assert_eq!(msg.box_data, vec![0x01, 0x23, 0x45, 0xab, 0xcd, 0xef]);
            assert_eq!(msg.nickname, None);
        }

        #[test]
        fn invalid_mac() {
            match IncomingMessage::from_urlencoded_bytes(TEST_PAYLOAD, "nevergonnaletyoudown") {
                Err(ApiError::InvalidMac) => { /* good! */ }
                other => panic!("Unexpected result: {:?}", other),
            }
        }
    }

    mod decrypt_box {
        use crypto_secretbox::aead::OsRng;

        use crypto_box::aead::AeadCore;

        use super::*;

        #[test]
        fn decrypt() {
            let a_sk = SecretKey::generate(&mut OsRng);
            let a_pk = a_sk.public_key();

            let b_sk = SecretKey::generate(&mut OsRng);
            let b_pk = b_sk.public_key();

            let a_box = SalsaBox::new(&b_pk, &a_sk);

            let nonce = SalsaBox::generate_nonce(&mut OsRng);

            let box_data = a_box
                .encrypt(
                    &nonce,
                    Payload::from([/* data */ 1, 2, 42, /* padding */ 3, 3, 3].as_ref()),
                )
                .expect("Failed to encrypt data");

            let msg = IncomingMessage {
                from: "AAAAAAAA".into(),
                to: "*BBBBBBB".into(),
                message_id: "00112233".into(),
                date: 0,
                nonce: nonce.to_vec(),
                box_data,
                nickname: None,
            };

            // Bad public key
            let err = msg.decrypt_box(&b_pk, &b_sk).unwrap_err();
            assert_eq!(err, CryptoError::DecryptionFailed);

            // Success
            let decrypted = msg.decrypt_box(&a_pk, &b_sk).unwrap();
            assert_eq!(decrypted, vec![1, 2, 42]);
        }

        #[test]
        fn decrypt_bad_nonce() {
            let sk = SecretKey::generate(&mut OsRng);
            let pk = sk.public_key();
            let msg = IncomingMessage {
                from: "AAAAAAAA".into(),
                to: "*BBBBBBB".into(),
                message_id: "00112233".into(),
                date: 0,
                nonce: vec![1, 2, 3, 4], // Nonce too short!
                box_data: vec![0],
                nickname: None,
            };

            let err = msg.decrypt_box(&pk, &sk).unwrap_err();
            assert_eq!(err, CryptoError::BadNonce);
        }

        #[test]
        fn decrypt_bad_padding() {
            let a_sk = SecretKey::generate(&mut OsRng);
            let a_pk = a_sk.public_key();

            let b_sk = SecretKey::generate(&mut OsRng);
            let b_pk = b_sk.public_key();

            let nonce = SalsaBox::generate_nonce(&mut OsRng);

            let a_box = SalsaBox::new(&b_pk, &a_sk);

            let box_data = a_box
                .encrypt(
                    &nonce,
                    Payload::from([/* data */ 1, 2, 42 /* no padding */].as_ref()),
                )
                .expect("Failed to encrypt data");

            let msg = IncomingMessage {
                from: "AAAAAAAA".into(),
                to: "*BBBBBBB".into(),
                message_id: "00112233".into(),
                date: 0,
                nonce: nonce.to_vec(),
                box_data,
                nickname: None,
            };

            // Bad padding
            let err = msg.decrypt_box(&a_pk, &b_sk).unwrap_err();
            assert_eq!(err, CryptoError::BadPadding);
        }
    }
}
