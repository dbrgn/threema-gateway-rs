//! Example: Send E2EE text, edit after 2s and delete after 4s.
#![allow(clippy::print_stdout, clippy::unwrap_used, reason = "Example code")]

use std::{process, time::Duration};

use docopt::Docopt;
use threema_gateway::{
    ApiBuilder, EncryptedMessage,
    protocol::{
        MessageId,
        e2e::{
            edit_delete::DeleteMessage,
            typing_indicator::{TypingIndicatorMessage, TypingStatus},
        },
    },
};
use tokio::time::sleep;

const USAGE: &str = "
Usage: send_e2e_edit_delete [options] <from> <to> <secret> <private-key> <text>...

Options:
    -h, --help    Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|error| error.exit());

    // Command line arguments
    let from = args.get_str("<from>");
    let to = args.get_str("<to>");
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
    let recipient_key = api.lookup_pubkey(to).await.unwrap_or_else(|error| {
        eprintln!("Could not fetch public key: {error}");
        process::exit(1);
    });

    // Helper function
    let send = async |encrypted: EncryptedMessage, msgtype: &'static str| {
        let msg_id = api.send(to, &encrypted, false).await;
        match msg_id {
            Ok(id) => {
                println!("Sent {msgtype} message. Message id is {id}.");
                MessageId::from_hex_le(&id).expect("message id returned by server should be valid")
            }
            Err(error) => {
                eprintln!("Could not send message: {error}");
                process::exit(1);
            }
        }
    };

    // Send text message
    let text = api
        .encode_and_encrypt(&text.into(), &recipient_key)
        .expect("encoding text message failed");
    let text_message_id = send(text, "text").await;

    // TODO: Edit after 2s
    sleep(Duration::from_secs(2)).await;

    // Delete after 4s
    sleep(Duration::from_secs(2)).await;
    let delete = api
        .encode_and_encrypt(&DeleteMessage::new(text_message_id).into(), &recipient_key)
        .expect("encoding not-typing indicator failed");
    send(delete, "delete").await;
}
