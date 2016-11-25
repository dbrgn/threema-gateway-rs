use std::io::Read;
use hyper::Client;
use hyper::header::ContentType;
use hyper::mime::{Mime, TopLevel, SubLevel};
use url::form_urlencoded;
use data_encoding::hex;


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
