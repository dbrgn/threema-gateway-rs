//! Send and receive messages.

use std::io::Read;
use std::borrow::Cow;

use hyper::client::{Client, Response};
use hyper::header::{ContentType};
use hyper::mime::{Mime, TopLevel, SubLevel};
use hyper::status::{StatusCode};
use url::form_urlencoded;
use data_encoding::hex;

use ::errors::ApiError;


/// Map HTTP response status code to an ApiError if it isn't "200".
fn map_response_codes(response: &Response) -> Result<(), ApiError> {
    match response.status {
        // 200
        StatusCode::Ok => Ok(()),
        // 400
        StatusCode::BadRequest => Err(ApiError::BadSenderOrRecipient),
        // 401
        StatusCode::Unauthorized => Err(ApiError::BadCredentials),
        // 402
        StatusCode::PaymentRequired => Err(ApiError::NoCredits),
        // 404
        StatusCode::NotFound => Err(ApiError::BadId),
        // 413
        StatusCode::PayloadTooLarge => Err(ApiError::MessageTooLong),
        // 500
        StatusCode::InternalServerError => Err(ApiError::ServerError),
        e @ _ => Err(ApiError::Other(format!("Bad response status code: {}", e))),
    }
}

/// Fetch the public key for the specified Threema ID.
///
/// For the end-to-end encrypted mode, you need the public key of the recipient
/// in order to encrypt a message. While it's best to obtain this directly from
/// the recipient (extract it from the QR code), this may not be convenient,
/// and therefore you can also look up the key associated with a given ID from
/// the server.
///
/// It is strongly recommended that you cache the public keys to avoid querying
/// the API for each message.
pub fn lookup_pubkey(our_id: &str, their_id: &str, secret: &str) -> Result<String, ApiError> {
    let client = Client::new();

    // Build URL
    let url = format!("https://msgapi.threema.ch/pubkeys/{}?from={}&secret={}", their_id, our_id, secret);

    // Send request
    let mut res = try!(client.get(&url).send());
    try!(map_response_codes(&res));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));
    Ok(body)
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
    let client = Client::new();

    // Check text length (max 3500 bytes)
    // Note: Strings in Rust are UTF8, so len() returns the byte count.
    if text.len() > 3500 {
        return Err(ApiError::MessageTooLong);
    }

    // Encode POST data
    let mut encoded = String::new();
    {
        let mut serializer = form_urlencoded::Serializer::new(&mut encoded);
        serializer.append_pair("from", from);
        serializer.append_pair("text", text);
        serializer.append_pair("secret", secret);
        match *to {
            Recipient::Id(ref id) => serializer.append_pair("to", id),
            Recipient::Phone(ref phone) => serializer.append_pair("phone", phone),
            Recipient::Email(ref email) => serializer.append_pair("email", email),
        };
    }

    println!("{}", &encoded);

    // Send request
    let mut res = try!(client
        .post("https://msgapi.threema.ch/send_simple")
        .body(&encoded)
        .header(ContentType(Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded, vec![])))
        .send());
    try!(map_response_codes(&res));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));

    Ok(body)
}


/// Send an already encrypted E2E message to the specified receiver.
pub fn send_e2e(from: &str, to: &str, secret: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<String, ApiError> {
    let client = Client::new();

    // Encode POST data
    let encoded: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("from", from)
        .append_pair("to", to)
        .append_pair("secret", secret)
        .append_pair("nonce", &hex::encode(nonce))
        .append_pair("box", &hex::encode(ciphertext))
        .finish();

    // Send request
    let mut res = try!(client
        .post("https://msgapi.threema.ch/send_e2e")
        .body(&encoded)
        .header(ContentType(Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded, vec![])))
        .send());
    try!(map_response_codes(&res));

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
