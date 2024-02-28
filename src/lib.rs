//! # Threema Gateway SDK for Rust
//!
//! This library makes it easy to use the [Threema
//! Gateway](https://gateway.threema.ch/) from Rust programs.
//!
//! Documentation of the HTTP API can be found at
//! [gateway.threema.ch](https://gateway.threema.ch/de/developer/api).
//!
//! Note: This library is fully asynchronous (because the underlying HTTP
//! client is async as well). To call the async methods, either call them from
//! an async context, or wrap the returned future in a `block_on` method
//! provided by an executor like tokio, async-std or smol.
//!
//! ## Example: Send simple (transport encrypted) message
//!
//! ```no_run
//! # tokio_test::block_on(async {
//! use threema_gateway::{ApiBuilder, Recipient};
//!
//! let from = "*YOUR_ID";
//! let to = Recipient::new_email("user@example.com");
//! let secret = "your-gateway-secret";
//! let text = "Very secret message!";
//!
//! // Send
//! let api = ApiBuilder::new(from, secret).into_simple();
//! match api.send(&to, &text).await {
//!     Ok(msg_id) => println!("Sent. Message id is {}.", msg_id),
//!     Err(e) => println!("Could not send message: {:?}", e),
//! }
//! # })
//! ```
//!
//! ## Example: Send end-to-end encrypted message
//!
//! ```no_run
//! # tokio_test::block_on(async {
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
//!     .with_private_key_str(private_key)
//!     .and_then(|builder| builder.into_e2e())
//!     .unwrap();
//!
//! // Fetch recipient public key
//! // Note: In a real application, you should cache the public key
//! let recipient_key = api.lookup_pubkey(to).await.unwrap();
//!
//! // Encrypt
//! let encrypted = api.encrypt_text_msg(text, &recipient_key)
//!     .expect("Could not encrypt text msg");
//!
//! // Send
//! match api.send(&to, &encrypted, false).await {
//!     Ok(msg_id) => println!("Sent. Message id is {}.", msg_id),
//!     Err(e) => println!("Could not send message: {:?}", e),
//! }
//! # })
//! ```
//!
//! For more examples, see the
//! [`examples/`](https://github.com/dbrgn/threema-gateway-rs/tree/master/examples) directory.

#![allow(clippy::collapsible_else_if)]
#![allow(clippy::too_many_arguments)]

#[macro_use]
extern crate log;

mod api;
mod connection;
mod crypto;
pub mod errors;
mod lookup;
#[cfg(feature = "receive")]
mod receive;
mod types;

pub use crypto_box::{PublicKey, SecretKey};
pub use crypto_secretbox::Nonce;

pub use crate::{
    api::{ApiBuilder, E2eApi, SimpleApi},
    connection::Recipient,
    crypto::{
        decrypt_file_data, encrypt, encrypt_file_data, encrypt_raw, EncryptedFileData,
        EncryptedMessage, FileData, Key, RecipientKey,
    },
    lookup::{Capabilities, LookupCriterion},
    types::{BlobId, FileMessage, FileMessageBuilder, MessageType, RenderingType},
};

#[cfg(feature = "receive")]
pub use crate::receive::IncomingMessage;

const MSGAPI_URL: &str = "https://msgapi.threema.ch";

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
