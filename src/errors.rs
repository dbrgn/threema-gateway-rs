//! Error types used in this library.

use std::{io::Error as IoError, str::Utf8Error};

use reqwest::Error as ReqwestError;
use thiserror::Error;

use crate::protocol::e2e::location::LocationMessageParseError;

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

    /// Too many requests, rate limit reached
    #[error("rate limit reached")]
    RateLimitReached,

    /// Error when sending request (via reqwest)
    #[error("request error: {0}")]
    RequestError(#[source] ReqwestError),

    /// Error when building request URL (via reqwest)
    #[error("request URL parse error: {0}")]
    RequestUrlParseError(#[from] url::ParseError),

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

/// Either an [`ApiError`] or a cache error.
#[derive(Debug, Error)]
pub enum ApiOrCacheError<C: core::error::Error> {
    /// API error, see contained [`ApiError`] value
    #[error("api error: {0}")]
    ApiError(ApiError),
    /// Cache error, see contained value `C`
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

/// Errors while decoding a message.
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    /// Message is empty (no type byte)
    #[error("message is empty (no type byte)")]
    EmptyMessage,

    /// Invalid UTF-8
    #[error("invalid utf-8: {0}")]
    InvalidUtf8(Utf8Error),

    /// JSON error
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Location message parse error
    #[error("location message parse error: {0}")]
    InvalidLocation(#[from] LocationMessageParseError),
}

/// Either a [`CryptoError`] or a [`MessageDecodeError`].
#[derive(Debug, Error)]
pub enum CryptoOrMessageDecodeError {
    /// The inner [`CryptoError`]
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// The [`MessageDecodeError`]
    #[error("decode error: {0}")]
    Decode(#[from] MessageDecodeError),
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
