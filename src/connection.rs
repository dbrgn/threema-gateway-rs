//! Send and receive messages.

use std::{borrow::Cow, collections::HashMap, ops::Not, str::FromStr};

use data_encoding::{BASE64, HEXLOWER};
use reqwest::{Client, StatusCode, multipart};
use serde::{Deserialize, Serialize};

use crate::{EncryptedMessage, SDK_HEADER, SDK_USER_AGENT, errors::ApiError, types::BlobId};

/// Map HTTP response status code to an ApiError if it isn't "200".
///
/// Optionally, you can pass in the meaning of a 400 response code.
pub(crate) fn map_response_code(
    status: StatusCode,
    bad_request_meaning: Option<ApiError>,
) -> Result<(), ApiError> {
    match status {
        // 200
        StatusCode::OK => Ok(()),
        // 400
        StatusCode::BAD_REQUEST => match bad_request_meaning {
            Some(error) => Err(error),
            None => Err(ApiError::Other(format!(
                "Bad response status code: {}",
                StatusCode::BAD_REQUEST
            ))),
        },
        // 401
        StatusCode::UNAUTHORIZED => Err(ApiError::BadCredentials),
        // 402
        StatusCode::PAYMENT_REQUIRED => Err(ApiError::NoCredits),
        // 404
        StatusCode::NOT_FOUND => Err(ApiError::IdNotFound),
        // 413
        StatusCode::PAYLOAD_TOO_LARGE => Err(ApiError::MessageTooLong),
        // 429
        StatusCode::TOO_MANY_REQUESTS => Err(ApiError::RateLimitReached),
        // 500
        StatusCode::INTERNAL_SERVER_ERROR => Err(ApiError::ServerError),
        e => Err(ApiError::Other(format!("Bad response status code: {}", e))),
    }
}

/// Different ways to specify a message recipient in basic mode.
#[derive(Debug)]
pub enum Recipient<'a> {
    /// Recipient identity (8 characters)
    Id(Cow<'a, str>),
    /// Recipient phone number (E.164), without leading +
    Phone(Cow<'a, str>),
    /// Recipient e-mail address
    Email(Cow<'a, str>),
}

impl<'a> Recipient<'a> {
    /// Create a `Recipient` from an identity.
    pub fn new_id<T: Into<Cow<'a, str>>>(id: T) -> Self {
        Recipient::Id(id.into())
    }

    /// Create a `Recipient` from a phone number.
    pub fn new_phone<T: Into<Cow<'a, str>>>(phone: T) -> Self {
        Recipient::Phone(phone.into())
    }

    /// Create a `Recipient` from an e-mail address.
    pub fn new_email<T: Into<Cow<'a, str>>>(email: T) -> Self {
        Recipient::Email(email.into())
    }
}

/// Send a message to the specified recipient in basic mode.
pub(crate) async fn send_simple(
    client: &Client,
    endpoint: &str,
    from: &str,
    to: &Recipient<'_>,
    secret: &str,
    text: &str,
) -> Result<String, ApiError> {
    log::debug!(
        "Sending transport encrypted message from {} to {:?}",
        from,
        to
    );

    // Check text length (max 3500 bytes)
    // Note: Strings in Rust are UTF8, so len() returns the byte count.
    if text.len() > 3500 {
        return Err(ApiError::MessageTooLong);
    }

    // Prepare POST data
    let mut params = HashMap::new();
    params.insert("from", from);
    params.insert("text", text);
    params.insert("secret", secret);
    match *to {
        Recipient::Id(ref id) => params.insert("to", id),
        Recipient::Phone(ref phone) => params.insert("phone", phone),
        Recipient::Email(ref email) => params.insert("email", email),
    };

    // Send request
    log::trace!("Sending HTTP request");
    let res = client
        .post(format!("{}/send_simple", endpoint))
        .form(&params)
        .header("accept", "application/json")
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    log::trace!("Received HTTP response");
    map_response_code(res.status(), Some(ApiError::BadSenderOrRecipient))?;

    // Read and return response body
    Ok(res.text().await?)
}

/// Send an encrypted E2E message to the specified recipient.
pub(crate) async fn send_e2e(
    client: &Client,
    endpoint: &str,
    from: &str,
    to: &str,
    secret: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    delivery_receipts: bool,
    additional_params: Option<HashMap<String, String>>,
) -> Result<String, ApiError> {
    log::debug!("Sending e2e encrypted message from {} to {}", from, to);

    // Prepare POST data
    let mut params = additional_params.unwrap_or_default();
    params.insert("from".into(), from.into());
    params.insert("to".into(), to.into());
    params.insert("secret".into(), secret.into());
    params.insert("nonce".into(), HEXLOWER.encode(nonce));
    params.insert("box".into(), HEXLOWER.encode(ciphertext));
    if !delivery_receipts {
        params.insert("noDeliveryReceipts".into(), "1".into());
    }

    // Send request
    log::trace!("Sending HTTP request");
    let res = client
        .post(format!("{}/send_e2e", endpoint))
        .form(&params)
        .header("accept", "application/json")
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    log::trace!("Received HTTP response");
    map_response_code(res.status(), Some(ApiError::BadSenderOrRecipient))?;

    // Read and return response body
    Ok(res.text().await?)
}

/// An end-to-end encrypted message for a specific recipient.
///
/// Used in the context of bulk sending.
pub struct BulkE2eMessage {
    /// Recipient Threema ID
    pub to: String,
    /// Encrypted message to send to the recipient above
    pub message: EncryptedMessage,
    /// When set to `false`, the recipient is requested not to send delivery
    /// receipts for this message.
    ///
    /// If you're unsure what value to use, set the flag to `true`.
    pub delivery_receipts: bool,
    /// When set to `false`, no push notification is triggered towards recipient.
    ///
    /// If you're unsure what value to use, set the flag to `true`.
    pub push: bool,
    /// When set to `true`, this message is marked as group message.
    ///
    /// In most cases, and unless you know what you're doing, this should be
    /// set to `false`.
    pub is_group_message: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonE2eMessage {
    to: String,
    nonce: String,
    r#box: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_delivery_receipts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_push: Option<bool>,
    group: Option<bool>,
}

/// Response to an E2E bulk message sending request.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum BulkE2eMessageSendStatus {
    /// Successful response with message ID
    Success {
        /// The message ID of the sent message
        #[serde(rename = "messageId")]
        message_id: String,
    },
    /// Error response with error code
    Error {
        /// The error code
        #[serde(rename = "errorCode")]
        error_code: i32,
    },
}

impl BulkE2eMessageSendStatus {
    /// Returns `true` if sending this message was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, BulkE2eMessageSendStatus::Success { .. })
    }

    /// Returns `true` if sending this message failed.
    pub fn is_error(&self) -> bool {
        matches!(self, BulkE2eMessageSendStatus::Error { .. })
    }

    /// Returns the message ID if the message was sent successfully, or `None` if it failed.
    pub fn message_id(&self) -> Option<&str> {
        match self {
            BulkE2eMessageSendStatus::Success { message_id } => Some(message_id),
            BulkE2eMessageSendStatus::Error { .. } => None,
        }
    }

    /// Returns the error code if the message failed to send.
    pub fn error_code(&self) -> Option<i32> {
        match self {
            BulkE2eMessageSendStatus::Success { .. } => None,
            BulkE2eMessageSendStatus::Error { error_code } => Some(*error_code),
        }
    }
}

/// Send multiple encrypted E2E messages.
pub(crate) async fn send_e2e_bulk(
    client: &Client,
    endpoint: &str,
    from: &str,
    secret: &str,
    messages: &[&BulkE2eMessage],
    same_message_id: bool,
) -> Result<Vec<BulkE2eMessageSendStatus>, ApiError> {
    log::debug!(
        "Sending e2e encrypted messages from {} to {} recipients",
        from,
        messages.len()
    );

    // Prepare POST data
    let mut params: HashMap<&str, String> = HashMap::new();
    params.insert("from", from.into());
    params.insert("secret", secret.into());
    if same_message_id {
        params.insert("sameMessageId", "1".to_string());
    }
    let messages: Vec<JsonE2eMessage> = messages
        .iter()
        .map(|m| {
            let no_delivery_receipts = m.delivery_receipts.not().then_some(true);
            let no_push = m.push.not().then_some(true);
            let group = m.is_group_message.not().then_some(true);
            JsonE2eMessage {
                to: m.to.clone(),
                nonce: BASE64.encode(&m.message.nonce),
                r#box: BASE64.encode(&m.message.ciphertext),
                no_delivery_receipts,
                no_push,
                group,
            }
        })
        .collect();
    // Send request
    log::trace!("Sending HTTP request");
    let res = client
        .post(format!("{}/send_e2e_bulk", endpoint))
        .query(&params)
        .json(&messages)
        .header("accept", "application/json")
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    log::trace!("Received HTTP response");
    map_response_code(res.status(), None)?;

    // Read and return response body
    Ok(res.json().await?)
}

/// Upload a blob to the blob server.
pub(crate) async fn blob_upload(
    client: &Client,
    endpoint: &str,
    from: &str,
    secret: &str,
    data: &[u8],
    persist: bool,
    additional_params: Option<HashMap<String, String>>,
) -> Result<BlobId, ApiError> {
    // Build URL
    let url = format!("{}/upload_blob", endpoint);
    let mut params = vec![("from", from), ("secret", secret)];
    if persist {
        params.push(("persist", "1"));
    }

    // Build multipart/form-data request body
    let mut form = multipart::Form::new();
    form = form.part(
        "blob",
        multipart::Part::bytes(data.to_vec())
            .mime_str("application/octet-stream")
            .expect("Could not parse MIME string"),
    );
    if let Some(params) = additional_params {
        for (k, v) in params {
            form = form.text(k, v);
        }
    }

    // Send request
    let res = client
        .post(&url)
        .query(&params)
        .multipart(form)
        .header("accept", "text/plain")
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    map_response_code(res.status(), Some(ApiError::BadBlob))?;

    // Read response body containing blob ID
    BlobId::from_str(res.text().await?.trim())
}

/// Download a blob from the blob server.
pub(crate) async fn blob_download(
    client: &Client,
    endpoint: &str,
    from: &str,
    secret: &str,
    blob_id: &BlobId,
) -> Result<Vec<u8>, ApiError> {
    let url = reqwest::Url::parse(endpoint)?
        .join("blobs/")?
        .join(&blob_id.to_string())?;

    // Send request
    let res = client
        .get(url)
        .header(SDK_HEADER, SDK_USER_AGENT)
        .query(&[("from", from), ("secret", secret)])
        .send()
        .await?;
    map_response_code(res.status(), Some(ApiError::BadBlob))?;

    // Read response bytes
    Ok(res.bytes().await?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{MSGAPI_URL, errors::ApiError};

    #[tokio::test]
    async fn test_simple_max_length_ok() {
        let text: String = "à".repeat(3500 / 2);
        let client = Client::new();
        let result = send_simple(
            &client,
            MSGAPI_URL,
            "TESTTEST",
            &Recipient::new_id("ECHOECHO"),
            "secret",
            &text,
        )
        .await;
        if let Err(ApiError::MessageTooLong) = result {
            panic!()
        }
    }

    #[tokio::test]
    async fn test_simple_max_length_too_long() {
        let mut text: String = "à".repeat(3500 / 2);
        text.push('x');
        let client = Client::new();
        let result = send_simple(
            &client,
            MSGAPI_URL,
            "TESTTEST",
            &Recipient::new_id("ECHOECHO"),
            "secret",
            &text,
        )
        .await;
        match result {
            Err(ApiError::MessageTooLong) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_bulk_e2e_send_status_json_parsing() {
        // Test success status with messageId
        let success_json = r#"{"messageId": "abc123def456"}"#;
        let success_status: BulkE2eMessageSendStatus = serde_json::from_str(success_json).unwrap();
        match success_status {
            BulkE2eMessageSendStatus::Success { message_id } => {
                assert_eq!(message_id, "abc123def456");
            }
            _ => panic!("Expected Success variant"),
        }

        // Test error status with errorCode
        let error_json = r#"{"errorCode": 404}"#;
        let error_status: BulkE2eMessageSendStatus = serde_json::from_str(error_json).unwrap();
        match error_status {
            BulkE2eMessageSendStatus::Error { error_code } => {
                assert_eq!(error_code, 404);
            }
            _ => panic!("Expected Error variant"),
        }

        // Test success status with extra fields (should still work)
        let success_with_extra_json = r#"{"messageId": "xyz789", "extraField": "ignored"}"#;
        let success_with_extra: BulkE2eMessageSendStatus =
            serde_json::from_str(success_with_extra_json).unwrap();
        match success_with_extra {
            BulkE2eMessageSendStatus::Success { message_id } => {
                assert_eq!(message_id, "xyz789");
            }
            _ => panic!("Expected Success variant"),
        }

        // Test error status with extra fields (should still work)
        let error_with_extra_json = r#"{"errorCode": 500, "description": "Internal server error"}"#;
        let error_with_extra: BulkE2eMessageSendStatus =
            serde_json::from_str(error_with_extra_json).unwrap();
        match error_with_extra {
            BulkE2eMessageSendStatus::Error { error_code } => {
                assert_eq!(error_code, 500);
            }
            _ => panic!("Expected Error variant"),
        }

        // Test that invalid JSON fails gracefully
        let invalid_json = r#"{"invalidField": "value"}"#;
        let invalid_result: Result<BulkE2eMessageSendStatus, _> =
            serde_json::from_str(invalid_json);
        assert!(invalid_result.is_err(), "Should fail to parse invalid JSON");

        // Test that empty JSON fails gracefully
        let empty_json = r#"{}"#;
        let empty_result: Result<BulkE2eMessageSendStatus, _> = serde_json::from_str(empty_json);
        assert!(empty_result.is_err(), "Should fail to parse empty JSON");
    }

    #[test]
    fn test_bulk_e2e_status_convenience_methods() {
        // Test success status convenience methods
        let success_json = r#"{"messageId": "test123"}"#;
        let success_status: BulkE2eMessageSendStatus = serde_json::from_str(success_json).unwrap();
        assert!(success_status.is_success());
        assert!(!success_status.is_error());
        assert_eq!(success_status.message_id(), Some("test123"));
        assert_eq!(success_status.error_code(), None);

        // Test error status convenience methods
        let error_json = r#"{"errorCode": 404}"#;
        let error_status: BulkE2eMessageSendStatus = serde_json::from_str(error_json).unwrap();
        assert!(!error_status.is_success());
        assert!(error_status.is_error());
        assert_eq!(error_status.message_id(), None);
        assert_eq!(error_status.error_code(), Some(404));
    }
}
