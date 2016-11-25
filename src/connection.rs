use std::io::Read;
use hyper::Client;
use hyper::header::ContentType;
use hyper::mime::{Mime, TopLevel, SubLevel};
use url::form_urlencoded;
use data_encoding::hex;


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
pub fn lookup_pubkey(our_id: &str, their_id: &str, secret: &str) -> String {
    let client = Client::new();
    let url = format!("https://msgapi.threema.ch/pubkeys/{}?from={}&secret={}", their_id, our_id, secret);
    let mut res = client.get(&url).send().unwrap();
    let mut body = String::new();
    res.read_to_string(&mut body).expect("Could not read response body");
    body
}

/// Send an already encrypted E2E message to the specified receiver.
pub fn send_e2e(from: &str, to: &str, secret: &str, nonce: &[u8], ciphertext: &[u8]) -> String {
    let client = Client::new();

    let encoded: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("from", from)
        .append_pair("to", to)
        .append_pair("secret", secret)
        .append_pair("nonce", &hex::encode(nonce))
        .append_pair("box", &hex::encode(ciphertext))
        .finish();

    let mut res = client
        .post("https://msgapi.threema.ch/send_e2e")
        .body(&encoded)
        .header(ContentType(Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded, vec![])))
        .send()
        .unwrap();

    let mut body = String::new();
    res.read_to_string(&mut body).expect("Could not read response body");

    body
}
