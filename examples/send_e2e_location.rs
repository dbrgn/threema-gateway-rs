//! Example: Send E2EE location message
#![allow(clippy::print_stdout, clippy::unwrap_used, reason = "Example code")]

use std::process;

use docopt::Docopt;
use threema_gateway::{ApiBuilder, protocol::e2e::location::LocationMessage};

const USAGE: &str = "
Usage: send_e2e_location [options] <from> <to> <secret> <private-key> <latitude> <longitude>

Options:
    --accuracy <meters>   Location accuracy in meters
    --address <address>   Full address matching the coordinates
    --name <name>         Name of the point of interest (requires --address)
    -h, --help            Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Parse args

    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|error| error.exit());

    let from = args.get_str("<from>");
    let to = args.get_str("<to>");
    let secret = args.get_str("<secret>");
    let private_key = args.get_str("<private-key>");
    let latitude: f64 = args.get_str("<latitude>").parse().unwrap_or_else(|error| {
        println!("Invalid latitude: {error}");
        process::exit(1);
    });
    let longitude: f64 = args.get_str("<longitude>").parse().unwrap_or_else(|error| {
        println!("Invalid longitude: {error}");
        process::exit(1);
    });
    let accuracy: Option<f64> = match args.get_str("--accuracy") {
        "" => None,
        val => Some(val.parse().unwrap_or_else(|error| {
            println!("Invalid accuracy: {error}");
            process::exit(1);
        })),
    };
    let address = match args.get_str("--address") {
        "" => None,
        val => Some(val),
    };
    let name = match args.get_str("--name") {
        "" => None,
        val => Some(val),
    };

    // Create API instance
    let api = ApiBuilder::new(from, secret)
        .with_private_key_str(private_key)
        .and_then(ApiBuilder::into_e2e)
        .unwrap();

    // Build message
    let msg = LocationMessage::builder(latitude, longitude)
        .accuracy_opt(accuracy)
        .address_opt(address)
        .name_opt(name)
        .build()
        .unwrap_or_else(|error| {
            println!("Could not build location message: {error}");
            process::exit(1);
        });

    // Fetch public key
    let recipient_key = api.lookup_pubkey(to).await.unwrap_or_else(|error| {
        println!("Could not fetch public key: {error}");
        process::exit(1);
    });

    // Encrypt message
    let encrypted = api
        .encrypt_location_msg(&msg, &recipient_key)
        .unwrap_or_else(|error| {
            println!("Could not encrypt location msg: {error}");
            process::exit(1);
        });
    let msg_id = api.send(to, &encrypted, false).await;
    match msg_id {
        Ok(id) => println!("Sent. Message id is {id}."),
        Err(error) => println!("Could not send message: {error}"),
    }
}
