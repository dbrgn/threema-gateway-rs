//! Example: Lookup credits
#![allow(clippy::print_stdout, clippy::unwrap_used, reason = "Example code")]

use std::process;

use docopt::Docopt;
use threema_gateway::{ApiBuilder, ThreemaId};

const USAGE: &str = "
Usage: lookup_credits [options] <from> <secret>

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
    let secret = args.get_str("<secret>");

    println!("Looking up credits");

    // Look up ID
    let api = ApiBuilder::new(from, secret).into_simple();
    match api.lookup_credits().await {
        Err(error) => {
            println!("Could not look up credits: {error}");
            process::exit(1);
        }
        Ok(credits) => println!("You have {credits} credits remaining"),
    }
}
