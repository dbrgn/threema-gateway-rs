//! Example: Send E2EE image
#![allow(
    clippy::print_stdout,
    clippy::use_debug,
    clippy::unwrap_used,
    reason = "Example code"
)]

use std::{ffi::OsStr, fs, path::Path, process};

use docopt::Docopt;
use threema_gateway::ApiBuilder;

const USAGE: &str = "
Usage: send_e2e_image [options] <from> <to> <secret> <private-key> <path-to-jpegfile>

Options:
    -h, --help    Show this help
";

/// Try or exit.
macro_rules! etry {
    ($result:expr, $msg:expr) => {{
        $result.unwrap_or_else(|error| {
            eprintln!("{}: {}", $msg, error);
            process::exit(1_i32);
        })
    }};
}

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
    let path = Path::new(args.get_str("<path-to-jpegfile>"));

    // Make sure that the file exists
    if !path.exists() {
        println!("File at {path:?} does not exist");
        process::exit(1);
    }
    if path.extension() != Some(OsStr::new("jpg")) {
        println!("File at {path:?} must end with .jpg");
        process::exit(1);
    }

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
        .with_private_key_str(private_key)
        .and_then(ApiBuilder::into_e2e)
        .unwrap();

    // Fetch recipient public key
    // Note: In a real application, you should cache the public key
    let recipient_key = api.lookup_pubkey(to).await.unwrap_or_else(|error| {
        println!("Could not fetch public key: {error}");
        process::exit(1);
    });

    // Encrypt image
    let img_data = etry!(fs::read(path), "Could not read file");
    let encrypted_image = api
        .encrypt_raw(&img_data, &recipient_key)
        .unwrap_or_else(|_| {
            println!("Could encrypt raw msg");
            process::exit(1);
        });

    // Upload image to blob server
    let blob_id = api
        .blob_upload(&encrypted_image, false)
        .await
        .unwrap_or_else(|error| {
            println!("Could not upload image to blob server: {error}");
            process::exit(1);
        });

    // Create image message
    let msg = api
        .encrypt_image_msg(
            &blob_id,
            u32::try_from(img_data.len()).expect("Image data length does not fit in u32"),
            &encrypted_image.nonce,
            &recipient_key,
        )
        .unwrap_or_else(|error| {
            println!("Could not encrypt image msg: {error}");
            process::exit(1);
        });

    // Send
    let msg_id = api.send(to, &msg, false).await;
    match msg_id {
        Ok(id) => println!("Sent. Message id is {id}."),
        Err(error) => println!("Could not send message: {error}"),
    }
}
