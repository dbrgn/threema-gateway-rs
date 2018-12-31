//! Send and receive messages.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Read;

use reqwest::{Client, StatusCode};
use data_encoding::HEXLOWER;

use ::errors::ApiError;
use ::types::BlobId;


/// Map HTTP response status code to an ApiError if it isn't "200".
///
/// Optionally, you can pass in the meaning of a 400 response code.
pub(crate) fn map_response_code(
    status: &StatusCode,
    bad_request_meaning: Option<ApiError>,
) -> Result<(), ApiError> {
    match *status {
        // 200
        StatusCode::OK => Ok(()),
        // 400
        StatusCode::BAD_REQUEST => match bad_request_meaning {
            Some(error) => Err(error),
            None => Err(ApiError::Other(format!("Bad response status code: {}", StatusCode::BAD_REQUEST))),
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
        e @ _ => Err(ApiError::Other(format!("Bad response status code: {}", e))),
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
pub(crate) fn send_simple(
    endpoint: &str,
    from: &str,
    to: &Recipient,
    secret: &str,
    text: &str,
) -> Result<String, ApiError> {
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
    let mut res = Client::new().post(&format!("{}/send_simple", endpoint))
        .form(&params)
        .header("accept", "application/json")
        .send()?;
    try!(map_response_code(&res.status(), Some(ApiError::BadSenderOrRecipient)));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));

    Ok(body)
}

/// Send an encrypted E2E message to the specified recipient.
pub(crate) fn send_e2e(
    endpoint: &str,
    from: &str,
    to: &str,
    secret: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    additional_params: Option<HashMap<String, String>>,
) -> Result<String, ApiError> {
    // Prepare POST data
    let mut params = match additional_params {
        Some(p) => p,
        None => HashMap::new(),
    };
    params.insert("from".into(), from.into());
    params.insert("to".into(), to.into());
    params.insert("secret".into(), secret.into());
    params.insert("nonce".into(), HEXLOWER.encode(nonce));
    params.insert("box".into(), HEXLOWER.encode(ciphertext));

    // Send request
    let mut res = Client::new().post(&format!("{}/send_e2e", endpoint))
        .form(&params)
        .header("accept", "application/json")
        .send()?;
    try!(map_response_code(&res.status(), Some(ApiError::BadSenderOrRecipient)));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));

    Ok(body)
}

/// Upload a blob to the blob server.
pub(crate) fn blob_upload(
    endpoint: &str,
    from: &str,
    secret: &str,
    data: &[u8],
) -> Result<BlobId, ApiError> {
    // Build URL
    let url = format!("{}/upload_blob?from={}&secret={}", endpoint, from, secret);

    // Build multipart/form-data request body
    let boundary = "3ma-d84f64f5-a138-4b0a-9e25-339257990c81-3ma".to_string();
    let mut req_body = Vec::new();
    req_body.extend_from_slice("--".as_bytes());
    req_body.extend_from_slice(&boundary.as_bytes());
    req_body.extend_from_slice("\r\n".as_bytes());
    req_body.extend_from_slice("Content-Disposition: form-data; name=\"blob\"\r\n".as_bytes());
    req_body.extend_from_slice("Content-Type: application/octet-stream\r\n\r\n".as_bytes());
    req_body.extend_from_slice(data);
    req_body.extend_from_slice("\r\n--".as_bytes());
    req_body.extend_from_slice(&boundary.as_bytes());
    req_body.extend_from_slice("--\r\n".as_bytes());

    // Send request
    let mimetype = format!("multipart/form-data; boundary={}", boundary);
    let mut res = Client::new().post(&url)
        .body(req_body)
        .header("accept", "text/plain")
        .header("content-type", mimetype)
        .send()?;
    try!(map_response_code(&res.status(), Some(ApiError::BadBlob)));

    // Read response body containing blob ID
    let mut body = String::new();
    res.read_to_string(&mut body)?;

    BlobId::from_str(body.trim())
}

#[cfg(test)]
mod tests {
    use std::iter::repeat;
    use ::MSGAPI_URL;
    use ::errors::ApiError;
    use super::*;

    #[test]
    fn test_simple_max_length_ok() {
        let text: String = repeat("à").take(3500 / 2).collect();
        let result = send_simple(MSGAPI_URL, "TESTTEST", &Recipient::new_id("ECHOECHO"), "secret", &text);
        match result {
            Err(ApiError::MessageTooLong) => panic!(),
            _ => (),
        }
    }

    #[test]
    fn test_simple_max_length_too_long() {
        let mut text: String = repeat("à").take(3500 / 2).collect();
        text.push('x');
        let result = send_simple(MSGAPI_URL, "TESTTEST", &Recipient::new_id("ECHOECHO"), "secret", &text);
        match result {
            Err(ApiError::MessageTooLong) => (),
            _ => panic!(),
        }
    }

}
