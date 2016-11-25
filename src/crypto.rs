use std::iter::repeat;

use sodiumoxide;
use sodiumoxide::crypto::box_;
use data_encoding::hex;
use rand::thread_rng;
use rand::distributions::{IndependentSample, Range};

use ::errors::CryptoError;


/// Encrypt data for the receiver.
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
    // TODO: Use rand until https://github.com/dnaq/sodiumoxide/pull/144 is done
    let between = Range::new(1, 255);
    let mut rng = thread_rng();
    let padding_amount: u8 = between.ind_sample(&mut rng) + 1;
    let padding = repeat(padding_amount).take(padding_amount as usize);
    let msgtype = repeat(1).take(1);
    let padded_plaintext: Vec<u8> = msgtype.chain(data.as_bytes().iter().cloned()).chain(padding).collect();

    let ciphertext = box_::seal(&padded_plaintext, &nonce, &theirpk, &oursk);
    Ok((ciphertext, nonce.0))
}
