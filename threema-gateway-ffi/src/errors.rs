//! Error types crossing the FFI boundary.

use threema_gateway as lib;

/// Errors raised by the Gateway API.
///
/// Match on specific variants for programmatic handling. The `Display`
/// representation is suitable for logging.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ApiError {
    /// The provided Threema ID was malformed (wrong length or invalid characters). Raised at the FFI boundary
    /// before any network call is made.
    #[error("invalid Threema ID: {message}")]
    InvalidThreemaId {
        /// Human-readable details.
        message: String,
    },

    /// The recipient identity is invalid or the account is not set up for the requested mode.
    #[error("bad sender or recipient")]
    BadSenderOrRecipient,

    /// Gateway ID or secret is incorrect.
    #[error("bad credentials")]
    BadCredentials,

    /// No credits remain on the Gateway account.
    #[error("no credits")]
    NoCredits,

    /// Target ID not found in the directory.
    #[error("id not found")]
    IdNotFound,

    /// Message exceeded the maximum size.
    #[error("message too long")]
    MessageTooLong,

    /// Internal Threema Gateway server error (5xx).
    #[error("server error")]
    ServerError,

    /// Provided hash had wrong length (phone or email hash lookup).
    #[error("bad hash length")]
    BadHashLength,

    /// Bad blob (size or content).
    #[error("bad blob")]
    BadBlob,

    /// Invalid blob ID.
    #[error("bad blob id")]
    BadBlobId,

    /// MAC verification failed on an incoming message.
    #[error("invalid MAC")]
    InvalidMac,

    /// Too many requests, rate limit reached.
    #[error("rate limit reached")]
    RateLimitReached,

    /// HTTP transport or network failure (DNS, TLS, connection, I/O, URL).
    #[error("transport error: {message}")]
    Transport {
        /// Human-readable details.
        message: String,
    },

    /// Could not parse the server response.
    #[error("parse error: {message}")]
    Parse {
        /// Human-readable details.
        message: String,
    },

    /// Any other API error not covered by the variants above. Inspect `message` for details before resorting
    /// to programmatic handling.
    #[error("other: {message}")]
    Other {
        /// Human-readable details.
        message: String,
    },
}

impl From<lib::errors::ApiError> for ApiError {
    fn from(err: lib::errors::ApiError) -> Self {
        // NOTE: keep this match exhaustive. When the upstream lib adds a new variant, this fails to compile
        // and forces an explicit mapping decision rather than silently funneling into `Other`.
        use lib::errors::ApiError as Upstream;
        match err {
            Upstream::BadSenderOrRecipient => Self::BadSenderOrRecipient,
            Upstream::BadCredentials => Self::BadCredentials,
            Upstream::NoCredits => Self::NoCredits,
            Upstream::IdNotFound => Self::IdNotFound,
            Upstream::MessageTooLong => Self::MessageTooLong,
            Upstream::ServerError => Self::ServerError,
            Upstream::BadHashLength => Self::BadHashLength,
            Upstream::BadBlob => Self::BadBlob,
            Upstream::BadBlobId => Self::BadBlobId,
            Upstream::InvalidMac => Self::InvalidMac,
            Upstream::RateLimitReached => Self::RateLimitReached,
            Upstream::RequestError(error) => Self::Transport {
                message: error.to_string(),
            },
            Upstream::RequestUrlParseError(error) => Self::Transport {
                message: error.to_string(),
            },
            Upstream::IoError(error) => Self::Transport {
                message: error.to_string(),
            },
            Upstream::ParseError(message) => Self::Parse { message },
            Upstream::Other(message) => Self::Other { message },
        }
    }
}

impl From<lib::ThreemaIdError> for ApiError {
    fn from(err: lib::ThreemaIdError) -> Self {
        Self::InvalidThreemaId {
            message: err.to_string(),
        }
    }
}
