use std::io::Read;

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
        StatusCode::Ok => Ok(()),
        StatusCode::Unauthorized => Err(ApiError::BadCredentials),
        StatusCode::NotFound => Err(ApiError::BadId),
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
