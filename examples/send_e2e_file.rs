use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process;

use docopt::Docopt;
use threema_gateway::{encrypt_file_data, ApiBuilder, FileMessage, RecipientKey, RenderingType};

const USAGE: &str = "
Usage: send_e2e_file [options] <from> <to> <secret> <private-key> <path-to-file> [<path-to-thumbnail>]

Options:
    -h, --help    Show this help
";

/// Try or exit.
macro_rules! etry {
    ($result:expr, $msg:expr) => {{
        $result.unwrap_or_else(|e| {
            println!("{}: {}", $msg, e);
            process::exit(1);
        })
    }};
}

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
    let filepath = Path::new(args.get_str("<path-to-file>"));
    let thumbpath = match args.get_str("<path-to-thumbnail>") {
        "" => None,
        p => Some(Path::new(p)),
    };

    // Verify thumbnail file type
    if let Some(t) = thumbpath {
        if t.extension() != Some(OsStr::new("jpg")) {
            println!("Thumbnail at {:?} must end with .jpg", t);
            process::exit(1);
        }
    }

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
        .with_private_key_str(private_key)
        .and_then(|builder| builder.into_e2e())
        .unwrap();

    // Fetch public key
    // Note: In a real application, you should cache the public key
    let public_key = etry!(api.lookup_pubkey(to).await, "Could not fetch public key");
    let recipient_key: RecipientKey = etry!(public_key.parse(), "Error");

    // Read files
    let mut file = etry!(File::open(filepath), "Could not open file");
    let mut file_data: Vec<u8> = vec![];
    etry!(file.read_to_end(&mut file_data), "Could not read file");
    let thumb_data = match thumbpath {
        Some(p) => {
            let mut thumb = etry!(File::open(p), format!("Could not open thumbnail {:?}", p));
            let mut thumb_data: Vec<u8> = vec![];
            etry!(
                thumb.read_to_end(&mut thumb_data),
                format!("Could not read thumbnail {:?}", p)
            );
            Some(thumb_data)
        }
        None => None,
    };

    // Encrypt file data
    let (encrypted_file, encrypted_thumb, key) =
        encrypt_file_data(&file_data, thumb_data.as_deref());

    // Upload files to blob server
    let file_blob_id = etry!(
        api.blob_upload_raw(&encrypted_file, false).await,
        "Could not upload file to blob server"
    );
    let thumb_blob_id = if let Some(et) = encrypted_thumb {
        let blob_id = etry!(
            api.blob_upload_raw(&et, false).await,
            "Could not upload thumbnail to blob server"
        );
        let thumbnail_media_type =
            mime_guess::from_path(&thumbpath.unwrap()).first_or_octet_stream();
        Some((blob_id, thumbnail_media_type))
    } else {
        None
    };

    // Create file message
    let file_media_type = mime_guess::from_path(&filepath).first_or_octet_stream();
    let file_name = filepath.file_name().and_then(OsStr::to_str);
    let msg = FileMessage::builder(file_blob_id, key, file_media_type, file_data.len() as u32)
        .thumbnail_opt(thumb_blob_id)
        .file_name_opt(file_name)
        .description("File message description")
        .rendering_type(RenderingType::File)
        .build()
        .expect("Could not build FileMessage");
    let encrypted = api.encrypt_file_msg(&msg, &recipient_key);

    // Send
    let msg_id = api.send(&to, &encrypted, false).await;
    match msg_id {
        Ok(id) => println!("Sent. Message id is {}.", id),
        Err(e) => println!("Could not send message: {}", e),
    }
}
