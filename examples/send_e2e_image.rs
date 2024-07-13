use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process;

use docopt::Docopt;
use threema_gateway::ApiBuilder;

const USAGE: &str = "
Usage: send_e2e_image [options] <from> <to> <secret> <private-key> <path-to-jpegfile>

Options:
    -h, --help    Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let from = args.get_str("<from>");
    let to = args.get_str("<to>");
    let secret = args.get_str("<secret>");
    let private_key = args.get_str("<private-key>");
    let path = Path::new(args.get_str("<path-to-jpegfile>"));

    // Make sure that the file exists
    if !path.exists() {
        println!("File at {:?} does not exist", path);
        process::exit(1);
    }
    if path.extension() != Some(OsStr::new("jpg")) {
        println!("File at {:?} must end with .jpg", path);
        process::exit(1);
    }

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
        .with_private_key_str(private_key)
        .and_then(|builder| builder.into_e2e())
        .unwrap();

    // Fetch recipient public key
    // Note: In a real application, you should cache the public key
    let recipient_key = api.lookup_pubkey(to).await.unwrap_or_else(|e| {
        println!("Could not fetch public key: {}", e);
        process::exit(1);
    });

    // Encrypt image
    let mut file = File::open(path).unwrap_or_else(|e| {
        println!("Could not open file: {}", e);
        process::exit(1);
    });
    let mut img_data: Vec<u8> = vec![];
    file.read_to_end(&mut img_data).unwrap_or_else(|e| {
        println!("Could not read file: {}", e);
        process::exit(1);
    });
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
        .unwrap_or_else(|e| {
            println!("Could not upload image to blob server: {}", e);
            process::exit(1);
        });

    // Create image message
    let msg = api
        .encrypt_image_msg(
            &blob_id,
            img_data.len() as u32,
            &encrypted_image.nonce,
            &recipient_key,
        )
        .unwrap_or_else(|e| {
            println!("Could not encrypt image msg: {e}");
            process::exit(1);
        });

    // Send
    let msg_id = api.send(to, &msg, false).await;
    match msg_id {
        Ok(id) => println!("Sent. Message id is {}.", id),
        Err(e) => println!("Could not send message: {}", e),
    }
}
