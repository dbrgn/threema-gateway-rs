//! Threema Gateway SDK for Rust
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
//! use threema_gateway::connection::{Recipient, send_simple};
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
//! ## Example: Send e2e-encrypted message
//!
//! ```no_run
//! use threema_gateway::crypto::encrypt;
//! use threema_gateway::connection::{lookup_pubkey, send_e2e};
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
//! let (ciphertext, nonce) = encrypt(&text, &public_key, &private_key).unwrap();
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

extern crate url;
extern crate hyper;
extern crate sodiumoxide;
extern crate data_encoding;
extern crate rand;
#[macro_use] extern crate quick_error;

pub mod crypto;
pub mod connection;
pub mod errors;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
