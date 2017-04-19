//! Encrypt and decrypt messages.

use std::convert::Into;
use std::iter::repeat;

use sodiumoxide;
use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use sodiumoxide::randombytes::randombytes_into;


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

/// A message type.
pub enum MessageType {
    Text,
    Image,
    Video,
    File,
    DeliveryReceipt,
}

impl Into<u8> for MessageType {
    fn into(self) -> u8 {
        match self {
            MessageType::Text => 0x01,
            MessageType::Image => 0x02,
            MessageType::Video => 0x13,
            MessageType::File => 0x17,
            MessageType::DeliveryReceipt => 0x80,
        }
    }
}

/// Encrypt data for the recipient. Return an [`EncryptedMessage`](struct.EncryptedMessage.html).
pub fn encrypt_raw(data: &[u8], public_key: &PublicKey, private_key: &SecretKey) -> EncryptedMessage {
    if !sodiumoxide::init() {
        panic!("Could not initialize sodiumoxide library.");
    }
    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(&data, &nonce, public_key, private_key);
    EncryptedMessage {
        ciphertext: ciphertext,
        nonce: nonce.0,
    }
}

/// Encrypt a message for the recipient. Return an [`EncryptedMessage`](struct.EncryptedMessage.html).
pub fn encrypt(data: &[u8],
               msgtype: MessageType,
               public_key: &PublicKey,
               private_key: &SecretKey)
               -> EncryptedMessage {

    // Add random amount of PKCS#7 style padding
    let padding_amount = random_padding_amount();
    let padding = repeat(padding_amount).take(padding_amount as usize);
    let msgtype_byte = repeat(msgtype.into()).take(1);
    let padded_plaintext: Vec<u8> = msgtype_byte.chain(data.iter().cloned()).chain(padding).collect();

    // Encrypt
    encrypt_raw(&padded_plaintext, &public_key, &private_key)
}

#[cfg(test)]
mod test {

    use super::random_padding_amount;

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
        let random_numbers = (1..100).map(|_| random_padding_amount()).collect::<Vec<u8>>();
        let first = random_numbers[0];
        assert!(!random_numbers.iter().all(|n| *n == first));
    }

}
