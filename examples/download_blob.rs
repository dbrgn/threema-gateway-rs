use std::process;

use data_encoding::HEXLOWER_PERMISSIVE;
use docopt::Docopt;
use threema_gateway::{decrypt_file_data, ApiBuilder, BlobId, EncryptedFileData, Key};

const USAGE: &str = "
Usage: download_blob [options] <our-id> <secret> <private-key> <blob-id> [<blob-key>]

Options:
    -h, --help    Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let our_id = args.get_str("<our-id>");
    let secret = args.get_str("<secret>");
    let private_key = args.get_str("<private-key>");
    let blob_id: BlobId = match args.get_str("<blob-id>").parse() {
        Ok(val) => val,
        Err(e) => {
            eprintln!("Could not decode blob ID from hex: {}", e);
            process::exit(1);
        }
    };
    let blob_key_raw = args.get_str("<blob-key>");
    let blob_key = if !blob_key_raw.is_empty() {
        let bytes = HEXLOWER_PERMISSIVE
            .decode(blob_key_raw.as_bytes())
            .expect("Invalid blob key");
        Some(Key::clone_from_slice(bytes.as_ref()))
    } else {
        None
    };

    // Create E2eApi instance
    let api = ApiBuilder::new(our_id, secret)
        .with_private_key_str(private_key)
        .and_then(|builder| builder.into_e2e())
        .unwrap();

    // Download blob
    println!("Downloading blob with ID {}...", blob_id);
    let bytes = match api.blob_download(&blob_id).await {
        Err(e) => {
            eprintln!("Could not download blob: {}", e);
            process::exit(1);
        }
        Ok(bytes) => {
            println!("Downloaded {} blob bytes:", bytes.len());
            bytes
        }
    };
    if let Some(key) = blob_key {
        let decrypted = decrypt_file_data(
            &EncryptedFileData {
                file: bytes,
                thumbnail: None,
            },
            &key,
        )
        .expect("Could not decrypt file data");
        println!(
            "Decrypted bytes: {}",
            HEXLOWER_PERMISSIVE.encode(&decrypted.file)
        );
    } else {
        println!("Encrypted bytes: {}", HEXLOWER_PERMISSIVE.encode(&bytes));
    }
}
