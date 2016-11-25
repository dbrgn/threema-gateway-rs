use std::iter::repeat;

use sodiumoxide;
use sodiumoxide::crypto::box_;
use data_encoding::hex;
use rand::thread_rng;
use rand::distributions::{IndependentSample, Range};


pub fn encrypt(data: &str) -> (Vec<u8>, [u8; 24]) {
    if !sodiumoxide::init() {
        panic!("Could not initialize sodiumoxide library.");
    }

    let oursk_string: &'static str = "";
    let theirpk_string: &'static str = "";
    let oursk = box_::SecretKey::from_slice(&hex::decode(oursk_string.as_bytes()).unwrap()).unwrap();
    let theirpk = box_::PublicKey::from_slice(&hex::decode(theirpk_string.as_bytes()).unwrap()).unwrap();

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
    (ciphertext, nonce.0)
}
