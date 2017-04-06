//! Send and receive messages.

use std::io::Read;
use std::borrow::Cow;
use std::collections::HashMap;

use reqwest::{Client, StatusCode};
use reqwest::header::Accept;
use data_encoding::hex;

use ::errors::ApiError;
use ::MSGAPI_URL;


/// Map HTTP response status code to an ApiError if it isn't "200".
///
/// Optionally, you can pass in the meaning of a 400 response code.
pub fn map_response_code(status: &StatusCode, bad_request_meaning: Option<ApiError>)
                         -> Result<(), ApiError> {
    match *status {
        // 200
        StatusCode::Ok => Ok(()),
        // 400
        StatusCode::BadRequest => match bad_request_meaning {
            Some(error) => Err(error),
            None => Err(ApiError::Other(format!("Bad response status code: {}", StatusCode::BadRequest))),
        },
        // 401
        StatusCode::Unauthorized => Err(ApiError::BadCredentials),
        // 402
        StatusCode::PaymentRequired => Err(ApiError::NoCredits),
        // 404
        StatusCode::NotFound => Err(ApiError::IdNotFound),
        // 413
        StatusCode::PayloadTooLarge => Err(ApiError::MessageTooLong),
        // 500
        StatusCode::InternalServerError => Err(ApiError::ServerError),
        e @ _ => Err(ApiError::Other(format!("Bad response status code: {}", e))),
    }
}

/// Different ways to specify a message recipient in basic mode
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
///
/// Note that this mode of sending messages does not provide end-to-end
/// encryption, only transport encryption between your host and the Threema
/// Gateway server.
pub fn send_simple(from: &str, to: &Recipient, secret: &str, text: &str) -> Result<String, ApiError> {

    let client = Client::new().expect("Could not initialize HTTP client");

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
    let mut res = try!(client.post(&format!("{}/send_simple", MSGAPI_URL))
        .form(&params)
        .header(Accept::json())
        .send());
    try!(map_response_code(res.status(), Some(ApiError::BadSenderOrRecipient)));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));

    Ok(body)
}


/// Send an already encrypted E2E message to the specified receiver.
pub fn send_e2e(from: &str, to: &str, secret: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<String, ApiError> {
    let client = Client::new().expect("Could not initialize HTTP client");

    // Prepare POST data
    let params = [
        ("from", from),
        ("to", to),
        ("secret", secret),
        ("nonce", &hex::encode(nonce)),
        ("box", &hex::encode(ciphertext)),
    ];

    // Send request
    let mut res = try!(client.post(&format!("{}/send_e2e", MSGAPI_URL))
        .form(&params)
        .header(Accept::json())
        .send());
    try!(map_response_code(res.status(), Some(ApiError::BadSenderOrRecipient)));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));

    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::iter::repeat;
    use ::errors::ApiError;
    use super::*;

    #[test]
    fn test_max_length_ok() {
        let text: String = repeat("à").take(3500 / 2).collect();
        let result = send_simple("TESTTEST", &Recipient::new_id("ECHOECHO"), "secret", &text);
        match result {
            Err(ApiError::MessageTooLong) => panic!(),
            _ => (),
        }
    }

    #[test]
    fn test_max_length_too_long() {
        let mut text: String = repeat("à").take(3500 / 2).collect();
        text.push('x');
        let result = send_simple("TESTTEST", &Recipient::new_id("ECHOECHO"), "secret", &text);
        match result {
            Err(ApiError::MessageTooLong) => (),
            _ => panic!(),
        }
    }
}
