extern crate docopt;
extern crate threema_gateway;

use std::fs::File;
use std::process;
use docopt::Docopt;
use threema_gateway::{ApiBuilder};


const USAGE: &'static str = "
Usage: blob_upload_raw [options] <from> <secret> <private-key> <file>

Options:
    -h, --help    Show this help
";


fn main() {
    let args = Docopt::new(USAGE)
                      .and_then(|docopt| docopt.parse())
                      .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let from = args.get_str("<from>");
    let secret = args.get_str("<secret>");
    let private_key = args.get_str("<private-key>");
    let filepath = args.get_str("<file>");

    // Create E2eApi instance
    let api = ApiBuilder::new(from, secret)
                         .with_private_key_str(private_key)
                         .and_then(|builder| builder.into_e2e())
                         .unwrap();

    // Open file
    let file = File::open(filepath).unwrap_or_else(|e| {
        println!("Could not open file: {}", e);
        process::exit(1);
    });

    // Upload
    let response = api.upload_raw(file);

    match response {
        Ok(bid) => println!("Uploaded. Blob ID: {}", bid),
        Err(e) => println!("Could not upload blob: {}", e),
    }
}
