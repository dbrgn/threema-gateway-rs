extern crate docopt;
extern crate threema_gateway;

use std::process;
use docopt::Docopt;
use threema_gateway::{ApiBuilder, RecipientKey, lookup_pubkey, send_e2e};


const USAGE: &'static str = "
Usage: send_e2e [options] <from> <to> <secret> <private-key> <text>...

Options:
    -h, --help    Show this help
";


fn main() {
    let args = Docopt::new(USAGE)
                      .and_then(|docopt| docopt.parse())
                      .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let from = args.get_str("<from>");
    let to = args.get_str("<to>");
    let secret = args.get_str("<secret>");
    let private_key = args.get_str("<private-key>");
    let text = args.get_vec("<text>").join(" ");

    // Fetch public key
    // Note: In a real application, you should cache the public key
    let public_key = lookup_pubkey(from, to, secret).unwrap_or_else(|e| {
        println!("Could not fetch public key: {:?}", e);
        process::exit(1);
    });

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
                         .with_private_key_str(private_key)
                         .and_then(|builder| builder.into_e2e())
                         .unwrap();

    // Encrypt and send
    let recipient_key = RecipientKey::from_str(&public_key).unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(1);
    });
    let encrypted = api.encrypt(text.as_bytes(), &recipient_key);
    let msg_id = send_e2e(&from, &to, &secret, &encrypted.nonce, &encrypted.ciphertext);

    match msg_id {
        Ok(id) => println!("Sent. Message id is {}.", id),
        Err(e) => println!("Could not send message: {:?}", e),
    }
}
