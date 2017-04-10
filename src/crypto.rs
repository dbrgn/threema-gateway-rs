//! Encrypt and decrypt messages.

use std::iter::repeat;

use sodiumoxide;
use sodiumoxide::crypto::box_;
use sodiumoxide::randombytes::randombytes_into;
use data_encoding::hex;

use ::errors::CryptoError;


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

/// Encrypt data for the receiver. Return a tuple `(ciphertext, nonce)`.
pub fn encrypt(data: &str, pub_key: &str, priv_key: &str) -> Result<(Vec<u8>, [u8; 24]), CryptoError> {
    if !sodiumoxide::init() {
        panic!("Could not initialize sodiumoxide library.");
    }

    // TODO: to_uppercase() allocates a new String. This is necessary because
    // hex decoding only accepts uppercase letters. Would be nice to get rid of
    // that.
    let pub_key_bytes = try!(hex::decode(pub_key.to_uppercase().as_bytes())
                                 .map_err(|e| format!("Could not decode public key hex string: {}", e)));
    let priv_key_bytes = try!(hex::decode(priv_key.to_uppercase().as_bytes())
                                 .map_err(|e| format!("Could not decode private key hex string: {}", e)));
    let oursk = box_::SecretKey::from_slice(&priv_key_bytes).unwrap();
    let theirpk = box_::PublicKey::from_slice(&pub_key_bytes).unwrap();

    let nonce = box_::gen_nonce();

    // Add random amount of PKCS#7 padding
    // Note: Use randombytes_uniform if https://github.com/dnaq/sodiumoxide/pull/144 is merged
    let padding_amount = random_padding_amount();
    let padding = repeat(padding_amount).take(padding_amount as usize);
    let msgtype = repeat(1).take(1);
    let padded_plaintext: Vec<u8> = msgtype.chain(data.as_bytes().iter().cloned()).chain(padding).collect();

    let ciphertext = box_::seal(&padded_plaintext, &nonce, &theirpk, &oursk);
    Ok((ciphertext, nonce.0))
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
