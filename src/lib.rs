//! # Threema Gateway SDK for Rust
//!
//! [![Travis CI][travis-ci-badge]][travis-ci]
//! [![Crates.io][crates-io-badge]][crates-io]
//! [![Rust][rust-badge]][github]
//!
//! This library makes it easy to use the [Threema
//! Gateway](https://gateway.threema.ch/) from Rust programs.
//!
//! Documentation of the HTTP API can be found here:
//! https://gateway.threema.ch/de/developer/api
//!
//! ## Example: Send simple (transport encrypted) message
//!
//! ```no_run
//! use threema_gateway::{Recipient, send_simple};
//!
//! let from = "*YOUR_ID";
//! let to = Recipient::new_email("user@example.com");
//! let secret = "your-gateway-secret";
//! let text = "Very secret message!";
//!
//! // Send
//! match send_simple(&from, &to, &secret, &text) {
//!     Ok(msg_id) => println!("Sent. Message id is {}.", msg_id),
//!     Err(e) => println!("Could not send message: {:?}", e),
//! }
//! ```
//!
//! ## Example: Send end-to-end encrypted message
//!
//! ```no_run
//! use threema_gateway::{lookup_pubkey, encrypt_from_str, send_e2e};
//!
//! let from = "*YOUR_ID";
//! let to = "ECHOECHO";
//! let secret = "your-gateway-secret";
//! let private_key = "your-private-key";
//! let text = "Very secret message!";
//!
//! // Fetch public key
//! // Note: In a real application, you should cache the public key
//! let public_key = lookup_pubkey(from, to, secret).unwrap();
//!
//! // Encrypt
//! // (Note: If you already have your public and private keys available as
//! // byte arrays, you can use the `encrypt` function instead.
//! let (ciphertext, nonce) = encrypt_from_str(&text, &public_key, &private_key).unwrap();
//!
//! // Send
//! match send_e2e(&from, &to, &secret, &nonce, &ciphertext) {
//!     Ok(msg_id) => println!("Sent. Message id is {}.", msg_id),
//!     Err(e) => println!("Could not send message: {:?}", e),
//! }
//! ```
//!
//! For more examples, see the
//! [`examples/`](https://github.com/dbrgn/threema-gateway-rs/tree/master/examples) directory.
//!
//!
//! <!-- Badges -->
//! [travis-ci]: https://travis-ci.org/dbrgn/threema-gateway-rs
//! [travis-ci-badge]: https://img.shields.io/travis/dbrgn/threema-gateway-rs.svg?maxAge=3600
//! [crates-io]: https://crates.io/crates/threema-gateway
//! [crates-io-badge]: https://img.shields.io/crates/v/threema-gateway.svg?maxAge=3600
//! [github]: https://github.com/dbrgn/threema-gateway-rs
//! [rust-badge]: https://img.shields.io/badge/rust-1.9%2B-blue.svg?maxAge=3600

extern crate data_encoding;
#[macro_use] extern crate log;
extern crate reqwest;
extern crate sodiumoxide;
#[macro_use] extern crate quick_error;

mod connection;
mod crypto;
mod lookup;
pub mod errors;

pub use connection::{send_simple, send_e2e, Recipient};
pub use crypto::{encrypt, encrypt_from_str};
pub use lookup::{lookup_pubkey, lookup_id, LookupCriterion};

const MSGAPI_URL: &'static str = "https://msgapi.threema.ch";

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
