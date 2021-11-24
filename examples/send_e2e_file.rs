use std::{ffi::OsStr, fs::File, io::Read, path::Path, process};

use docopt::Docopt;
use threema_gateway::{encrypt_file_data, ApiBuilder, FileMessage, RenderingType};

const USAGE: &str = "
Usage: send_e2e_file [options] <from> <to> <secret> <private-key> <path-to-file>

Options:
    --thumbnail <path>       Optional path to thumbnail
    --caption <caption>      Optional caption
    --rendering-type <type>  Set the rendering type (file, media or sticker)
    -h, --help               Show this help
";

/// Try or exit.
macro_rules! etry {
    ($result:expr, $msg:expr) => {{
        $result.unwrap_or_else(|e| {
            eprintln!("{}: {}", $msg, e);
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
    let thumbpath = match args.get_str("--thumbnail") {
        "" => None,
        p => Some(Path::new(p)),
    };
    let rendering_type = match args.get_str("--rendering-type") {
        "" | "file" => RenderingType::File,
        "media" => RenderingType::Media,
        "sticker" => RenderingType::Sticker,
        other => {
            eprintln!("Invalid rendering type: {}", other);
            process::exit(1);
        }
    };
    let caption = match args.get_str("--caption") {
        "" => None,
        c => Some(c),
    };

    // Verify thumbnail file type
    if let Some(t) = thumbpath {
        if t.extension() != Some(OsStr::new("jpg")) {
            eprintln!("Thumbnail at {:?} must end with .jpg", t);
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
        .description_opt(caption)
        .rendering_type(rendering_type)
        .build()
        .expect("Could not build FileMessage");
    let encrypted = api.encrypt_file_msg(&msg, &public_key.into());

    // Send
    let msg_id = api.send(&to, &encrypted, false).await;
    match msg_id {
        Ok(id) => println!("Sent. Message id is {}.", id),
        Err(e) => println!("Could not send message: {}", e),
    }
}
