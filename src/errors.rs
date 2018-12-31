//! Error types used in this library.

use std::io::Error as IoError;

use quick_error::quick_error;
use reqwest::Error as ReqwestError;

quick_error! {
    /// Errors when interacting with the API.
    #[derive(Debug)]
    pub enum ApiError {
        /// The recipient identity is invalid or the account is not set up for basic mode
        BadSenderOrRecipient {}

        /// API identity or secret is incorrect
        BadCredentials {}

        /// No credits remain
        NoCredits {}

        /// Target ID not found
        IdNotFound {}

        /// Message is too long
        MessageTooLong {}

        /// Internal server error
        ServerError {}

        /// Wrong hash length
        BadHashLength {}

        /// Bad blob
        BadBlob {}

        /// Invalid blob ID
        BadBlobId {}

        /// Error when sending request (via reqwest)
        RequestError(err: ReqwestError) {
            from()
            display("RequestError: {}", err)
        }

        /// Error when reading response
        IoError(err: IoError) {
            from()
            display("IoError: {}", err)
        }

        /// Error while parsing response
        ParseError(msg: String) {
            display("ParseError: {}", msg)
        }

        /// Other
        Other(msg: String) {
            display("{}", msg)
        }
    }
}

quick_error! {
    /// Crypto related errors.
    #[derive(Debug)]
    pub enum CryptoError {
        /// Bad key
        BadKey(msg: String) {
            from()
        }
    }
}

quick_error! {
    /// Errors when interacting with the [`ApiBuilder`](struct.ApiBuilder.html).
    #[derive(Debug)]
    pub enum ApiBuilderError {
        /// No private key has been set.
        MissingKey {}
        /// Invalid libsodium private key.
        InvalidKey(msg: String) {}
    }
}
