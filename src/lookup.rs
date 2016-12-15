//! ID and public key lookups.

use std::io::Read;

use hyper::client::Client;

use ::errors::ApiError;
use ::connection::map_response_codes;


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
