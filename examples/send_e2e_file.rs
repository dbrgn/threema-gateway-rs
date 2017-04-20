extern crate docopt;
extern crate sodiumoxide;
extern crate threema_gateway;
extern crate mime_guess;

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process;
use docopt::Docopt;
use mime_guess::guess_mime_type;
use sodiumoxide::crypto::secretbox;
use threema_gateway::{ApiBuilder, RecipientKey};


const USAGE: &'static str = "
Usage: send_e2e_file [options] <from> <to> <secret> <private-key> <path-to-file> [<path-to-thumbnail>]

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
    let filepath = Path::new(args.get_str("<path-to-file>"));
    let thumbpath = match args.get_str("<path-to-thumbnail>") {
        "" => None,
        p @ _ => Some(Path::new(p))
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
    let public_key = api.lookup_pubkey(to).unwrap_or_else(|e| {
        println!("Could not fetch public key: {}", e);
        process::exit(1);
    });
    let recipient_key = RecipientKey::from_str(&public_key).unwrap_or_else(|e| {
        println!("{}", e);
        process::exit(1);
    });

    // Read files
    let mut file = File::open(filepath).unwrap_or_else(|e| {
        println!("Could not open file: {}", e);
        process::exit(1);
    });
    let mut file_data: Vec<u8> = vec![];
    file.read_to_end(&mut file_data).unwrap_or_else(|e| {
        println!("Could not read file: {}", e);
        process::exit(1);
    });
    let thumb_data = match thumbpath {
        Some(p) => {
            let mut thumb = File::open(p).unwrap_or_else(|e| {
                println!("Could not open thumbnail {:?}: {}", p, e);
                process::exit(1);
            });
            let mut thumb_data: Vec<u8> = vec![];
            thumb.read_to_end(&mut thumb_data).unwrap_or_else(|e| {
                println!("Could not read thumbnail {:?}: {}", p, e);
                process::exit(1);
            });
            Some(thumb_data)
        },
        None => None
    };

    // Make sure to init sodiumoxide library
    sodiumoxide::init();

    // Generate a random encryption key
    let key = secretbox::gen_key();
    let file_nonce = secretbox::Nonce([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
    let thumb_nonce = secretbox::Nonce([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2]);

    // Encrypt files
    let encrypted_file = secretbox::seal(&file_data, &file_nonce, &key);
    let encrypted_thumb = thumb_data.map(|t| secretbox::seal(&t, &thumb_nonce, &key));

    // Upload files to blob server
    let file_blob_id = api.blob_upload_raw(&encrypted_file).unwrap_or_else(|e| {
        println!("Could not upload file to blob server: {}", e);
        process::exit(1);
    });
    let thumb_blob_id = encrypted_thumb.map(|t| api.blob_upload_raw(&t).unwrap_or_else(|e| {
        println!("Could not upload thumbnail to blob server: {}", e);
        process::exit(1);
    }));

    // Create file message
    let mime_type = guess_mime_type(&filepath);
    let file_name = filepath.file_name().and_then(OsStr::to_str);
    let msg = api.encrypt_file_msg(&file_blob_id,
                                   thumb_blob_id.as_ref(),
                                   &key,
                                   &mime_type,
                                   file_name,
                                   file_data.len() as u32,
                                   Some("File message description"),
                                   &recipient_key);

    // Send
    let msg_id = api.send(&to, &msg);
    match msg_id {
        Ok(id) => println!("Sent. Message id is {}.", id),
        Err(e) => println!("Could not send message: {:?}", e),
    }
}
