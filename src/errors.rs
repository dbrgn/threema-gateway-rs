//! Error types used in this library.

use std::io::Error as IoError;

use reqwest::Error as ReqwestError;
use thiserror::Error;

/// Errors when interacting with the API.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The recipient identity is invalid or the account is not set up for basic mode
    #[error("bad sender or recipient")]
    BadSenderOrRecipient,

    /// API identity or secret is incorrect
    #[error("bad credentials")]
    BadCredentials,

    /// No credits remain
    #[error("no credits")]
    NoCredits,

    /// Target ID not found
    #[error("target ID not found")]
    IdNotFound,

    /// Message is too long
    #[error("message is too long")]
    MessageTooLong,

    /// Internal server error
    #[error("internal server error")]
    ServerError,

    /// Wrong hash length
    #[error("bad hash length")]
    BadHashLength,

    /// Bad blob
    #[error("bad blob")]
    BadBlob,

    /// Invalid blob ID
    #[error("bad blob ID")]
    BadBlobId,

    /// Invalid MAC
    #[error("invalid MAC")]
    InvalidMac,

    /// Error when sending request (via reqwest)
    #[error("request error: {0}")]
    RequestError(#[source] ReqwestError),

    /// Error when reading response
    #[error("I/O error: {0}")]
    IoError(#[from] IoError),

    /// Error while parsing response
    #[error("parse error: {0}")]
    ParseError(String),

    /// Other
    #[error("other: {0}")]
    Other(String),
}

impl From<ReqwestError> for ApiError {
    fn from(err: ReqwestError) -> Self {
        // Strip URL, as it might contain sensitive content (the API secret)
        Self::RequestError(err.without_url())
    }
}

#[derive(Debug, Error)]
pub enum ApiOrCacheError<C: std::error::Error> {
    #[error("api error: {0}")]
    ApiError(ApiError),
    #[error("cache error: {0}")]
    CacheError(C),
}

/// Crypto related errors.
#[derive(Debug, PartialEq, Clone, Error)]
pub enum CryptoError {
    /// Bad key
    #[error("bad key: {0}")]
    BadKey(String),

    /// Invalid nonce
    #[error("bad nonce")]
    BadNonce,

    /// Invalid PKCS#7 padding
    #[error("invalid padding")]
    BadPadding,

    /// Decryption failed
    #[error("decryption failed")]
    DecryptionFailed,

    /// Encryption failed
    #[error("encryption failed")]
    EncryptionFailed,
}

/// Errors when interacting with the [`ApiBuilder`](../struct.ApiBuilder.html).
#[derive(Debug, PartialEq, Clone, Error)]
pub enum ApiBuilderError {
    /// No private key has been set.
    #[error("missing private key")]
    MissingKey,

    /// Invalid libsodium private key.
    #[error("invalid libsodium private key: {0}")]
    InvalidKey(String),
}

/// Errors when interacting with the [`FileMessageBuilder`](../struct.FileMessageBuilder.html).
#[derive(Debug, PartialEq, Clone, Error)]
pub enum FileMessageBuilderError {
    /// Illegal combination of fields (e.g. setting the `animated` flag on a PDF file message).
    #[error("illegal combination: {0}")]
    IllegalCombination(&'static str),
}
