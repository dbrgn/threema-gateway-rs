//! Send and receive messages.

use std::{borrow::Cow, collections::HashMap, ops::Not as _, str::FromStr as _};

use data_encoding::{BASE64, HEXLOWER};
use log::{debug, trace};
use reqwest::{Client, multipart};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    EncryptedMessage, SDK_HEADER, SDK_USER_AGENT,
    errors::ApiError,
    protocol::{BlobId, MessageId, ThreemaId},
};

/// Map HTTP response status code to an [`ApiError`] if it isn't "200".
///
/// Optionally, you can pass in the meaning of a 400 response code.
pub(crate) fn map_response_code(
    status_code: u16,
    bad_request_meaning: Option<ApiError>,
) -> Result<(), ApiError> {
    match status_code {
        200 => Ok(()),
        other => Err(map_response_error_code(other, bad_request_meaning)),
    }
}

/// Map HTTP response error code to an [`ApiError`].
///
/// Optionally, you can pass in the meaning of a 400 response code.
pub(crate) fn map_response_error_code(
    status_code: u16,
    bad_request_meaning: Option<ApiError>,
) -> ApiError {
    match status_code {
        // Bad request
        400 => match bad_request_meaning {
            Some(error) => error,
            None => ApiError::Other("Bad request (HTTP 400)".to_owned()),
        },
        // Unauthorized
        401 => ApiError::BadCredentials,
        // Payment Required
        402 => ApiError::NoCredits,
        // Not Found
        404 => ApiError::IdNotFound,
        // Payload Too Large
        413 => ApiError::MessageTooLong,
        // Too Many Requests
        429 => ApiError::RateLimitReached,
        // Internal Server Error
        500 => ApiError::ServerError,
        // Unexpected code
        error => ApiError::Other(format!("Response status code: {error}")),
    }
}

/// Different ways to specify a message recipient in basic mode.
#[derive(Debug)]
pub enum Recipient<'cow> {
    /// Recipient identity (8 characters)
    Id(ThreemaId),
    /// Recipient phone number (E.164), without leading +
    Phone(Cow<'cow, str>),
    /// Recipient e-mail address
    Email(Cow<'cow, str>),
}

impl<'cow> Recipient<'cow> {
    /// Create a `Recipient` from an identity.
    #[must_use]
    pub fn new_id(id: ThreemaId) -> Self {
        Recipient::Id(id)
    }

    /// Create a `Recipient` from a phone number.
    pub fn new_phone<T: Into<Cow<'cow, str>>>(phone: T) -> Self {
        Recipient::Phone(phone.into())
    }

    /// Create a `Recipient` from an e-mail address.
    pub fn new_email<T: Into<Cow<'cow, str>>>(email: T) -> Self {
        Recipient::Email(email.into())
    }
}

/// Send a message to the specified recipient in basic mode.
pub(crate) async fn send_simple(
    client: &Client,
    endpoint: &str,
    from: &ThreemaId,
    to: &Recipient<'_>,
    secret: &str,
    text: &str,
) -> Result<MessageId, ApiError> {
    debug!("Sending transport encrypted message from {from} to {to:?}");

    // Check text length (max 3500 bytes)
    // Note: Strings in Rust are UTF8, so len() returns the byte count.
    if text.len() > 3500 {
        return Err(ApiError::MessageTooLong);
    }

    // Prepare POST data
    let mut params = HashMap::new();
    params.insert("from", from.as_str());
    params.insert("text", text);
    params.insert("secret", secret);
    match to {
        Recipient::Id(id) => params.insert("to", id.as_str()),
        Recipient::Phone(phone) => params.insert("phone", phone),
        Recipient::Email(email) => params.insert("email", email),
    };

    // Send request
    trace!("Sending HTTP request");
    let res = client
        .post(format!("{endpoint}/send_simple"))
        .form(&params)
        .header("accept", "application/json")
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    trace!("Received HTTP response");
    map_response_code(res.status().as_u16(), Some(ApiError::BadSenderOrRecipient))?;

    // Read and parse response body as message ID
    let body = res.text().await?;
    body.trim()
        .parse()
        .map_err(|err| ApiError::ParseError(format!("invalid message ID: {err}")))
}

/// Send an encrypted E2E message to the specified recipient.
#[expect(clippy::too_many_arguments, reason = "TODO refactor later")]
pub(crate) async fn send_e2e(
    client: &Client,
    endpoint: &str,
    from: &ThreemaId,
    to: &ThreemaId,
    secret: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    delivery_receipts: bool,
    additional_params: Option<HashMap<String, String>>,
) -> Result<MessageId, ApiError> {
    debug!("Sending e2e encrypted message from {from} to {to}");

    // Prepare POST data
    let mut params = additional_params.unwrap_or_default();
    params.insert("from".into(), from.to_string());
    params.insert("to".into(), to.to_string());
    params.insert("secret".into(), secret.into());
    params.insert("nonce".into(), HEXLOWER.encode(nonce));
    params.insert("box".into(), HEXLOWER.encode(ciphertext));
    if !delivery_receipts {
        params.insert("noDeliveryReceipts".into(), "1".into());
    }

    // Send request
    trace!("Sending HTTP request");
    let res = client
        .post(format!("{endpoint}/send_e2e"))
        .form(&params)
        .header("accept", "application/json")
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    trace!("Received HTTP response");
    map_response_code(res.status().as_u16(), Some(ApiError::BadSenderOrRecipient))?;

    // Read and parse response body as message ID
    let body = res.text().await?;
    body.trim()
        .parse()
        .map_err(|err| ApiError::ParseError(format!("invalid message ID: {err}")))
}

/// An end-to-end encrypted message for a specific recipient.
///
/// Used in the context of bulk sending.
pub struct BulkE2eMessage {
    /// Recipient Threema ID
    pub to: ThreemaId,
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

impl From<&BulkE2eMessage> for JsonE2eMessage {
    fn from(msg: &BulkE2eMessage) -> Self {
        let no_delivery_receipts = msg.delivery_receipts.not().then_some(true);
        let no_push = msg.push.not().then_some(true);
        let group = msg.is_group_message.then_some(true);
        JsonE2eMessage {
            to: msg.to.to_string(),
            nonce: BASE64.encode(&msg.message.nonce),
            r#box: BASE64.encode(&msg.message.ciphertext),
            no_delivery_receipts,
            no_push,
            group,
        }
    }
}

/// Custom deserializer for error codes that converts u16 to [`ApiError`]
fn deserialize_error_code<'de, D>(deserializer: D) -> Result<ApiError, D::Error>
where
    D: Deserializer<'de>,
{
    let code = u16::deserialize(deserializer)?;
    Ok(map_response_error_code(code, None))
}

/// Response to an E2E bulk message sending request.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum BulkE2eMessageSendStatus {
    /// Successful response with message ID
    Success {
        /// The message ID of the sent message
        #[serde(rename = "messageId")]
        message_id: MessageId,
    },
    /// Error response with error code
    Error {
        /// The error
        #[serde(rename = "errorCode", deserialize_with = "deserialize_error_code")]
        error: ApiError,
    },
}

impl BulkE2eMessageSendStatus {
    /// Returns `true` if sending this message was successful.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, BulkE2eMessageSendStatus::Success { .. })
    }

    /// Returns `true` if sending this message failed.
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, BulkE2eMessageSendStatus::Error { .. })
    }

    /// Returns the message ID if the message was sent successfully, or `None` if it failed.
    #[must_use]
    pub fn message_id(&self) -> Option<MessageId> {
        match self {
            BulkE2eMessageSendStatus::Success { message_id } => Some(*message_id),
            BulkE2eMessageSendStatus::Error { .. } => None,
        }
    }

    /// Returns the error if the message failed to send.
    #[must_use]
    pub fn error(&self) -> Option<&ApiError> {
        match self {
            BulkE2eMessageSendStatus::Success { .. } => None,
            BulkE2eMessageSendStatus::Error { error } => Some(error),
        }
    }
}

/// Send multiple encrypted E2E messages.
pub(crate) async fn send_e2e_bulk(
    client: &Client,
    endpoint: &str,
    from: &ThreemaId,
    secret: &str,
    messages: &[&BulkE2eMessage],
    same_message_id: bool,
) -> Result<Vec<BulkE2eMessageSendStatus>, ApiError> {
    debug!(
        "Sending e2e encrypted messages from {} to {} recipients",
        from,
        messages.len()
    );

    // Prepare POST data
    let mut params: HashMap<&str, String> = HashMap::new();
    params.insert("from", from.to_string());
    params.insert("secret", secret.into());
    if same_message_id {
        params.insert("sameMessageId", "1".to_owned());
    }
    let messages: Vec<JsonE2eMessage> = messages
        .iter()
        .map(|msg| JsonE2eMessage::from(*msg))
        .collect();

    // Send request
    trace!("Sending HTTP request");
    let res = client
        .post(format!("{endpoint}/send_e2e_bulk"))
        .query(&params)
        .json(&messages)
        .header("accept", "application/json")
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    trace!("Received HTTP response");
    map_response_code(res.status().as_u16(), None)?;

    // Read and return response body
    Ok(res.json().await?)
}

/// Upload a blob to the blob server.
pub(crate) async fn blob_upload(
    client: &Client,
    endpoint: &str,
    from: &ThreemaId,
    secret: &str,
    data: &[u8],
    persist: bool,
    additional_params: Option<HashMap<String, String>>,
) -> Result<BlobId, ApiError> {
    // Build URL
    let url = format!("{endpoint}/upload_blob");
    let mut params = vec![("from", from.as_str()), ("secret", secret)];
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
        for (key, val) in params {
            form = form.text(key, val);
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
    map_response_code(res.status().as_u16(), Some(ApiError::BadBlob))?;

    // Read response body containing blob ID
    BlobId::from_str(res.text().await?.trim())
}

/// Download a blob from the blob server.
pub(crate) async fn blob_download(
    client: &Client,
    endpoint: &str,
    from: &ThreemaId,
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
        .query(&[("from", from.as_str()), ("secret", secret)])
        .send()
        .await?;
    map_response_code(res.status().as_u16(), Some(ApiError::BadBlob))?;

    // Read response bytes
    Ok(res.bytes().await?.to_vec())
}

#[cfg(test)]
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "Tests"
)]
mod tests {
    use super::*;

    use crate::{MSGAPI_URL, errors::ApiError, protocol::MessageId};

    #[tokio::test]
    async fn simple_max_length_ok() {
        let text = "à".repeat(3500 / 2);
        let client = Client::new();
        let from = "TESTTEST".try_into().unwrap();
        let to_id = "ECHOECHO".try_into().unwrap();
        let result = send_simple(
            &client,
            MSGAPI_URL,
            &from,
            &Recipient::new_id(to_id),
            "secret",
            &text,
        )
        .await;
        if let Err(ApiError::MessageTooLong) = result {
            panic!()
        }
    }

    #[tokio::test]
    async fn simple_max_length_too_long() {
        let mut text = "à".repeat(3500 / 2);
        text.push('x');
        let client = Client::new();
        let from = "TESTTEST".try_into().unwrap();
        let to_id = "ECHOECHO".try_into().unwrap();
        let result = send_simple(
            &client,
            MSGAPI_URL,
            &from,
            &Recipient::new_id(to_id),
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
    fn bulk_e2e_send_status_json_parsing() {
        // Test success status with messageId
        let success_json = r#"{"messageId": "0102030405060708"}"#;
        let success_status: BulkE2eMessageSendStatus = serde_json::from_str(success_json).unwrap();
        if let BulkE2eMessageSendStatus::Success { message_id } = success_status {
            assert_eq!(
                message_id,
                MessageId::from_hex_le("0102030405060708").unwrap()
            );
        } else {
            panic!("Expected Success variant");
        }

        // Test error status with errorCode
        let error_json = r#"{"errorCode": 404}"#;
        let error_status: BulkE2eMessageSendStatus = serde_json::from_str(error_json).unwrap();
        if let BulkE2eMessageSendStatus::Error { error } = error_status {
            assert!(matches!(error, ApiError::IdNotFound));
        } else {
            panic!("Expected Error variant");
        }

        // Test success status with extra fields (should still work)
        let success_with_extra_json =
            r#"{"messageId": "a1b2c3d4e5f60718", "extraField": "ignored"}"#;
        let success_with_extra: BulkE2eMessageSendStatus =
            serde_json::from_str(success_with_extra_json).unwrap();
        if let BulkE2eMessageSendStatus::Success { message_id } = success_with_extra {
            assert_eq!(
                message_id,
                MessageId::from_hex_le("a1b2c3d4e5f60718").unwrap()
            );
        } else {
            panic!("Expected Success variant");
        }

        // Test error status with extra fields (should still work)
        let error_with_extra_json = r#"{"errorCode": 500, "description": "Internal server error"}"#;
        let error_with_extra: BulkE2eMessageSendStatus =
            serde_json::from_str(error_with_extra_json).unwrap();
        if let BulkE2eMessageSendStatus::Error { error } = error_with_extra {
            assert!(matches!(error, ApiError::ServerError));
        } else {
            panic!("Expected Error variant");
        }

        // Test that invalid JSON fails gracefully
        let invalid_json = r#"{"invalidField": "value"}"#;
        let invalid_result: Result<BulkE2eMessageSendStatus, _> =
            serde_json::from_str(invalid_json);
        assert!(invalid_result.is_err(), "Should fail to parse invalid JSON");

        // Test that empty JSON fails gracefully
        let empty_json = "{}";
        let empty_result: Result<BulkE2eMessageSendStatus, _> = serde_json::from_str(empty_json);
        assert!(empty_result.is_err(), "Should fail to parse empty JSON");
    }

    #[test]
    fn bulk_e2e_status_convenience_methods() {
        // Test success status convenience methods
        let success_json = r#"{"messageId": "0807060504030201"}"#;
        let success_status: BulkE2eMessageSendStatus = serde_json::from_str(success_json).unwrap();
        assert!(success_status.is_success());
        assert!(!success_status.is_error());
        assert_eq!(
            success_status.message_id(),
            Some(MessageId::from_hex_le("0807060504030201").unwrap()),
        );
        assert!(success_status.error().is_none());

        // Test error status convenience methods
        let error_json = r#"{"errorCode": 404}"#;
        let error_status: BulkE2eMessageSendStatus = serde_json::from_str(error_json).unwrap();
        assert!(!error_status.is_success());
        assert!(error_status.is_error());
        assert_eq!(error_status.message_id(), None);
        assert!(matches!(error_status.error(), Some(ApiError::IdNotFound)));
    }

    #[test]
    fn bulk_e2e_error_code_mapping() {
        // Test 400 -> ApiError::Other (bad request)
        let error_400_json = r#"{"errorCode": 400}"#;
        let error_400: BulkE2eMessageSendStatus = serde_json::from_str(error_400_json).unwrap();
        if let BulkE2eMessageSendStatus::Error { error } = error_400 {
            assert!(matches!(error, ApiError::Other(_)));
        } else {
            panic!("Expected Error variant");
        }

        // Test 402 -> ApiError::NoCredits
        let error_402_json = r#"{"errorCode": 402}"#;
        let error_402: BulkE2eMessageSendStatus = serde_json::from_str(error_402_json).unwrap();
        if let BulkE2eMessageSendStatus::Error { error } = error_402 {
            assert!(matches!(error, ApiError::NoCredits));
        } else {
            panic!("Expected Error variant");
        }

        // Test unknown error code -> ApiError::Other
        let error_999_json = r#"{"errorCode": 999}"#;
        let error_999: BulkE2eMessageSendStatus = serde_json::from_str(error_999_json).unwrap();
        if let BulkE2eMessageSendStatus::Error { error } = error_999 {
            assert!(matches!(error, ApiError::Other(_)));
        } else {
            panic!("Expected Error variant");
        }
    }

    mod json_e2e_message_from_bulk {
        use crypto_secretbox::{AeadCore as _, XSalsa20Poly1305, aead::OsRng};

        use super::*;

        #[test]
        fn optional_fields_none() {
            // When delivery_receipts=true, push=true, is_group_message=false,
            // the optional fields should be None
            let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
            let ciphertext = vec![10, 20, 30, 40];
            let bulk_msg = BulkE2eMessage {
                to: "ABCD1234".try_into().unwrap(),
                message: EncryptedMessage {
                    nonce,
                    ciphertext: ciphertext.clone(),
                },
                delivery_receipts: true,
                push: true,
                is_group_message: false,
            };

            let json_msg = JsonE2eMessage::from(&bulk_msg);

            assert_eq!(json_msg.to, "ABCD1234");
            assert_eq!(json_msg.nonce, BASE64.encode(&nonce));
            assert_eq!(json_msg.r#box, BASE64.encode(&ciphertext));
            assert_eq!(json_msg.no_delivery_receipts, None);
            assert_eq!(json_msg.no_push, None);
            assert_eq!(json_msg.group, None);
        }

        #[test]
        fn optional_fields_some() {
            // When delivery_receipts=false, push=false, is_group_message=true,
            // the optional fields should be Some(true)
            let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
            let ciphertext = vec![0xdd, 0xee, 0xff];
            let bulk_msg = BulkE2eMessage {
                to: "WXYZ9876".try_into().unwrap(),
                message: EncryptedMessage {
                    nonce,
                    ciphertext: ciphertext.clone(),
                },
                delivery_receipts: false,
                push: false,
                is_group_message: true,
            };

            let json_msg = JsonE2eMessage::from(&bulk_msg);

            assert_eq!(json_msg.to, "WXYZ9876");
            assert_eq!(json_msg.nonce, BASE64.encode(&nonce));
            assert_eq!(json_msg.r#box, BASE64.encode(&ciphertext));
            assert_eq!(json_msg.no_delivery_receipts, Some(true));
            assert_eq!(json_msg.no_push, Some(true));
            assert_eq!(json_msg.group, Some(true));
        }
    }
}
