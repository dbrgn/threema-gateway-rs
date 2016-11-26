//! Error types used in this library.

use std::io::Error as IoError;
use hyper::error::Error as HyperError;

quick_error! {
    #[derive(Debug)]
    pub enum ApiError {
        /// The recipient identity is invalid or the account is not set up for basic mode
        BadSenderOrRecipient {}

        /// API identity or secret is incorrect
        BadCredentials {}

        /// No credits remain
        NoCredits {}

        /// Target ID not found
        BadId {}

        /// Message is too long
        MessageTooLong {}

        /// Internal server error
        ServerError {}

        /// Error when sending request
        RequestError(err: HyperError) {
            from()
        }

        /// Error when reading response
        IoError(err: IoError) {
            from()
        }

        /// Other
        Other(msg: String) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum CryptoError {
        /// Bad key
        BadKey(msg: String) {
            from()
        }
    }
}
