//! ID and public key lookups.

use std::io::Read;

use hyper::client::Client;

use ::errors::ApiError;
use ::connection::map_response_codes;


#[derive(Debug, PartialEq)]
pub enum LookupCriterion {
    /// The phone number must be passed in E.164 format, without the leading `+`.
    Phone(String),
    /// The phone number must be passed as an HMAC-SHA256 hash of the E.164
    /// number without the leading `+`. The HMAC key is
    /// `85adf8226953f3d96cfd5d09bf29555eb955fcd8aa5ec4f9fcd869e258370723`
    /// (in hexadecimal).
    PhoneHash(String),
    /// The email address.
    Email(String),
    /// The lowercased and whitespace-trimmed email address must be hashed with
    /// HMAC-SHA256. The HMAC key is
    /// `30a5500fed9701fa6defdb610841900febb8e430881f7ad816826264ec09bad7`
    /// (in hexadecimal).
    EmailHash(String),
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
    try!(map_response_codes(&res, None));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));
    Ok(body)
}

/// Look up an ID in the Threema directory.
pub fn lookup_id(criterion: &LookupCriterion, our_id: &str, secret: &str) -> Result<String, ApiError> {
    let client = Client::new();

    // Build URL
    let url_base = match criterion {
        &LookupCriterion::Phone(ref val) => format!("https://msgapi.threema.ch/lookup/phone/{}", val),
        &LookupCriterion::PhoneHash(ref val) => format!("https://msgapi.threema.ch/lookup/phone_hash/{}", val),
        &LookupCriterion::Email(ref val) => format!("https://msgapi.threema.ch/lookup/email/{}", val),
        &LookupCriterion::EmailHash(ref val) => format!("https://msgapi.threema.ch/lookup/email_hash/{}", val),
    };
    let url = format!("{}?from={}&secret={}", url_base, our_id, secret);

    // Send request
    let mut res = try!(client.get(&url).send());
    try!(map_response_codes(&res, Some(ApiError::BadHashLength)));

    // Read and return response body
    let mut body = String::new();
    try!(res.read_to_string(&mut body));
    Ok(body)
}
