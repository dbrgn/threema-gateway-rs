//! # Threema Gateway SDK for Rust
//!
//! [![Travis CI](https://img.shields.io/travis/dbrgn/threema-gateway-rs.svg?maxAge=3600)](https://travis-ci.org/dbrgn/threema-gateway-rs)
//! [![Crates.io](https://img.shields.io/crates/v/threema-gateway.svg?maxAge=3600)](https://crates.io/crates/threema-gateway)
//! [![Rust](https://img.shields.io/badge/rust-1.21%2B-blue.svg?maxAge=3600)](https://github.com/dbrgn/threema-gateway-rs)
//!
//! This library makes it easy to use the [Threema
//! Gateway](https://gateway.threema.ch/) from Rust programs.
//!
//! Documentation of the HTTP API can be found at
//! [gateway.threema.ch](https://gateway.threema.ch/de/developer/api).
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
//! use threema_gateway::{ApiBuilder, RecipientKey};
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
//! let encrypted = api.encrypt_text_msg(text, &recipient_key);
//!
//! // Send
//! match api.send(&to, &encrypted) {
//!     Ok(msg_id) => println!("Sent. Message id is {}.", msg_id),
//!     Err(e) => println!("Could not send message: {:?}", e),
//! }
//! ```
//!
//! For more examples, see the
//! [`examples/`](https://github.com/dbrgn/threema-gateway-rs/tree/master/examples) directory.

extern crate byteorder;
extern crate data_encoding;
#[macro_use] extern crate log;
extern crate mime;
#[macro_use] extern crate quick_error;
extern crate reqwest;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate sodiumoxide;

mod api;
mod connection;
mod crypto;
mod lookup;
mod types;
pub mod errors;

pub use api::{ApiBuilder, E2eApi, SimpleApi};
pub use connection::{Recipient};
pub use crypto::{EncryptedMessage, RecipientKey};
pub use lookup::{LookupCriterion, Capabilities};
pub use types::{MessageType, BlobId};

const MSGAPI_URL: &'static str = "https://msgapi.threema.ch";

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
