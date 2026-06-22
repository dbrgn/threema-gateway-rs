//! Example: Send E2EE image (as a file message with media rendering type)
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::use_debug,
    reason = "Example code"
)]

use std::{ffi::OsStr, fs, path::Path, process};

use docopt::Docopt;
use imagesize::ImageType;
use threema_gateway::{
    ApiBuilder, FileData, ThreemaId, encrypt_file_data,
    protocol::e2e::file::{FileMessage, RenderingType},
};

const USAGE: &str = "
Usage: send_e2e_image [options] <from> <to> <secret> <private-key> <path-to-image-file>

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
    let from = ThreemaId::try_from(args.get_str("<from>")).unwrap();
    let to = ThreemaId::try_from(args.get_str("<to>")).unwrap();
    let secret = args.get_str("<secret>");
    let private_key = args.get_str("<private-key>");
    let path = Path::new(args.get_str("<path-to-image-file>"));

    // Make sure that the file exists
    if !path.exists() {
        eprintln!("File at {path:?} does not exist");
        process::exit(1);
    }

    // Read image file
    let img_data = etry!(fs::read(path), "Could not read file");
    let file_size_bytes =
        u32::try_from(img_data.len()).expect("Image data length does not fit in u32");

    // Ensure that file is a JPEG or PNG file
    let media_type = match imagesize::image_type(&img_data) {
        Ok(ImageType::Jpeg) => "image/jpeg",
        Ok(ImageType::Png) => "image/png",
        Ok(_other) => {
            eprintln!("File at {path:?} must be a JPG or PNG image");
            process::exit(1);
        }
        Err(_) => {
            eprintln!("Could not determine image type for file {path:?}");
            process::exit(1);
        }
    };

    // Extract image dimensions
    let dimensions = match imagesize::blob_size(&img_data) {
        Ok(size) => {
            let width = u32::try_from(size.width).expect("Image width does not fit in u32");
            let height = u32::try_from(size.height).expect("Image height does not fit in u32");
            Some((width, height))
        }
        Err(error) => {
            eprintln!("Warning: Could not determine image dimensions: {error}");
            None
        }
    };

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
        .with_private_key_str(private_key)
        .and_then(ApiBuilder::into_e2e)
        .unwrap();

    // Fetch recipient public key
    // Note: In a real application, you should cache the public key
    let recipient_key = etry!(api.lookup_pubkey(&to).await, "Could not fetch public key");

    // Encrypt file data
    //
    // NOTE: In real world code you should use a thumbnail re-scaled to
    // 512x512px. In this example, we skip the thumbnail to avoid having
    // to pull in an image downscaling dependency and re-use the full
    // sized file,
    let file_data = FileData {
        file: img_data.clone(),
        thumbnail: None,
    };
    let (encrypted, key) = etry!(encrypt_file_data(&file_data), "Could not encrypt file data");

    // Upload encrypted image to blob server
    let blob_id = etry!(
        api.blob_upload_raw(&encrypted.file, false).await,
        "Could not upload image to blob server"
    );

    // Build file message with media rendering type
    let file_name = path.file_name().and_then(OsStr::to_str);
    let mut builder = FileMessage::builder(blob_id, key, media_type, file_size_bytes)
        .file_name_opt(file_name)
        .rendering_type(RenderingType::Media)
        .animated(false);
    if let Some((width, height)) = dimensions {
        builder = builder.dimensions(height, width);
    }
    let msg = etry!(builder.build(), "Could not build FileMessage");

    // Encrypt and send
    let encrypted = etry!(
        api.encode_and_encrypt(&msg.into(), &recipient_key),
        "Could not encrypt message"
    );
    let msg_id = api.send(&to, &encrypted, false).await;
    match msg_id {
        Ok(id) => println!("Sent. Message id is {id}."),
        Err(error) => println!("Could not send message: {error}"),
    }
}
