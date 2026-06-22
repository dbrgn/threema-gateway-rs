//! Example: Send E2EE text with typing indicator indicating 2s of typing
#![allow(clippy::print_stdout, clippy::unwrap_used, reason = "Example code")]

use std::{process, time::Duration};

use docopt::Docopt;
use threema_gateway::{
    ApiBuilder, EncryptedMessage, ThreemaId,
    protocol::e2e::typing_indicator::{TypingIndicatorMessage, TypingStatus},
};
use tokio::time::sleep;

const USAGE: &str = "
Usage: send_e2e_typing_indicator [options] <from> <to> <secret> <private-key> <text>...

Options:
    -h, --help    Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|error| error.exit());

    // Command line arguments
    let from = ThreemaId::try_from(args.get_str("<from>")).unwrap();
    let to = ThreemaId::try_from(args.get_str("<to>")).unwrap();
    let secret = args.get_str("<secret>");
    let private_key = args.get_str("<private-key>");
    let text = args.get_vec("<text>").join(" ");

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
        .with_private_key_str(private_key)
        .and_then(ApiBuilder::into_e2e)
        .unwrap();

    // Fetch recipient public key
    // Note: In a real application, you should cache the public key
    let recipient_key = api.lookup_pubkey(&to).await.unwrap_or_else(|error| {
        println!("Could not fetch public key: {error}");
        process::exit(1);
    });

    // Prepare messages
    let is_typing = api
        .encode_and_encrypt(
            &TypingIndicatorMessage::new(TypingStatus::Typing).into(),
            &recipient_key,
        )
        .expect("encoding typing indicator failed");
    let text = api
        .encode_and_encrypt(&text.into(), &recipient_key)
        .expect("encoding text message failed");
    let stopped_typing = api
        .encode_and_encrypt(
            &TypingIndicatorMessage::new(TypingStatus::NotTyping).into(),
            &recipient_key,
        )
        .expect("encoding not-typing indicator failed");

    // Helper function
    let send = async |encrypted: EncryptedMessage, msgtype: &'static str| {
        let msg_id = api.send(&to, &encrypted, false).await;
        match msg_id {
            Ok(id) => println!("Sent {msgtype} message. Message id is {id}."),
            Err(error) => println!("Could not send message: {error}"),
        }
    };

    // Send (with typing indicator)
    send(is_typing, "is_typing").await;
    sleep(Duration::from_secs(2)).await;
    send(stopped_typing, "stopped_typing").await;
    send(text, "text").await;
}
