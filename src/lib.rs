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
//! use threema_gateway::{ApiBuilder, Recipient};
//!
//! let from = "*YOUR_ID";
//! let to = Recipient::new_email("user@example.com");
//! let secret = "your-gateway-secret";
//! let text = "Very secret message!";
//!
//! // Send
//! let api = ApiBuilder::new(from, secret).into_simple();
//! match api.send(&to, &text) {
//!     Ok(msg_id) => println!("Sent. Message id is {}.", msg_id),
//!     Err(e) => println!("Could not send message: {:?}", e),
//! }
//! ```
//!
//! ## Example: Send end-to-end encrypted message
//!
//! ```no_run
//! use threema_gateway::{ApiBuilder, RecipientKey, send_e2e};
//!
//! let from = "*YOUR_ID";
//! let to = "ECHOECHO";
//! let secret = "your-gateway-secret";
//! let private_key = "your-private-key";
//! let text = "Very secret message!";
//!
//! // Create E2eApi instance
//! let api = ApiBuilder::new(from, secret)
//!                      .with_private_key_str(private_key)
//!                      .and_then(|builder| builder.into_e2e())
//!                      .unwrap();
//!
//! // Fetch public key
//! // Note: In a real application, you should cache the public key
//! let public_key = api.lookup_pubkey(to).unwrap();
//!
//! // Encrypt
//! let recipient_key = RecipientKey::from_str(&public_key).unwrap();
//! let encrypted = api.encrypt(text.as_bytes(), &recipient_key);
//!
//! // Send
//! match send_e2e(&from, &to, &secret, &encrypted.nonce, &encrypted.ciphertext) {
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

mod api;
mod connection;
mod crypto;
mod lookup;
pub mod errors;

pub use api::{ApiBuilder, E2eApi, SimpleApi, RecipientKey};
pub use connection::{send_e2e, Recipient};
pub use crypto::{EncryptedMessage};
pub use lookup::{LookupCriterion};

const MSGAPI_URL: &'static str = "https://msgapi.threema.ch";

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
