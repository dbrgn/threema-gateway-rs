use std::process;

use docopt::Docopt;
use threema_gateway::{ApiBuilder, RecipientKey};

const USAGE: &str = "
Usage: send_e2e_text [options] <from> <to> <secret> <private-key> <text>...

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

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
        .with_private_key_str(private_key)
        .and_then(|builder| builder.into_e2e())
        .unwrap();

    // Fetch public key
    // Note: In a real application, you should cache the public key
    let public_key = api.lookup_pubkey(to).unwrap_or_else(|e| {
        println!("Could not fetch public key: {:?}", e);
        process::exit(1);
    });

    // Encrypt and send
    let recipient_key: RecipientKey = public_key.parse().unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(1);
    });
    let encrypted = api.encrypt_text_msg(&text, &recipient_key);
    let msg_id = api.send(&to, &encrypted);

    match msg_id {
        Ok(id) => println!("Sent. Message id is {}.", id),
        Err(e) => println!("Could not send message: {:?}", e),
    }
}
