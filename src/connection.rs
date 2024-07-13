//! Send and receive messages.

use std::{borrow::Cow, collections::HashMap, str::FromStr};

use data_encoding::HEXLOWER;
use reqwest::{multipart, Client, StatusCode};

use crate::{errors::ApiError, types::BlobId};

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
    pub fn new_id<T: Into<Cow<'a, str>>>(id: T) -> Self {
        Recipient::Id(id.into())
    }

    pub fn new_phone<T: Into<Cow<'a, str>>>(phone: T) -> Self {
        Recipient::Phone(phone.into())
    }

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
        .post(&format!("{}/send_simple", endpoint))
        .form(&params)
        .header("accept", "application/json")
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
        .post(&format!("{}/send_e2e", endpoint))
        .form(&params)
        .header("accept", "application/json")
        .send()
        .await?;
    log::trace!("Received HTTP response");
    map_response_code(res.status(), Some(ApiError::BadSenderOrRecipient))?;

    // Read and return response body
    Ok(res.text().await?)
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
    let mut url = format!("{}/upload_blob?from={}&secret={}", endpoint, from, secret);
    if persist {
        url.push_str("&persist=1");
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
        .multipart(form)
        .header("accept", "text/plain")
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
    // Build URL
    let url = format!(
        "{}/blobs/{}?from={}&secret={}",
        endpoint, blob_id, from, secret
    );

    // Send request
    let res = client.get(&url).send().await?;
    map_response_code(res.status(), Some(ApiError::BadBlob))?;

    // Read response bytes
    Ok(res.bytes().await?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{errors::ApiError, MSGAPI_URL};

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
}
