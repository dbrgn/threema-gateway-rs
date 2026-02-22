//! Example: Listen on specified host/port, decrypt and decode any incoming message
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::use_debug,
    reason = "Example code"
)]

use axum::{Router, body::Bytes, extract::State, http::StatusCode, routing::post};
use data_encoding::HEXLOWER_PERMISSIVE;
use docopt::Docopt;
use threema_gateway::{ApiBuilder, E2eApi, SecretKey};
use tokio::net::TcpListener;

const USAGE: &str = "
Usage: receive [options] <our-id> <secret> <private-key> <listen-addr>

The <listen-addr> argument should be in `host:port` format, for example `127.0.0.1:8000`.

Options:
    -h, --help    Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|error| error.exit());

    // Command line arguments
    let our_id = args.get_str("<our-id>");
    let secret = args.get_str("<secret>");
    let key_bytes = HEXLOWER_PERMISSIVE
        .decode(args.get_str("<private-key>").as_bytes())
        .unwrap_or_else(|_| {
            eprintln!("No private key provided");
            std::process::exit(1);
        });
    let private_key = SecretKey::from_slice(&key_bytes).unwrap_or_else(|_| {
        eprintln!("Invalid private key");
        std::process::exit(1);
    });
    let addr = args.get_str("<listen-addr>");

    // Create E2eApi instance
    let api = ApiBuilder::new(our_id, secret)
        .with_private_key(private_key)
        .into_e2e()
        .unwrap();

    // TODO: Use in-memory public key cache

    // Set up HTTP server on `host:port`, handle incoming POST requests to /callback
    let app = Router::new()
        .route("/callback", post(handle_callback))
        .with_state(api);
    let listener = TcpListener::bind(&addr).await.unwrap();
    println!("Listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_callback(State(api): State<E2eApi>, body: Bytes) -> StatusCode {
    let msg = match api.decode_incoming_message(&body) {
        Ok(msg) => msg,
        Err(error) => {
            eprintln!("Could not decode incoming message: {error}");
            return StatusCode::BAD_REQUEST;
        }
    };

    println!("Parsed and validated message from request:");
    println!("  From: {}", msg.from);
    println!("  To: {}", msg.to);
    println!("  Message ID: {}", msg.message_id);
    println!("  Timestamp: {}", msg.date);
    println!("  Sender nickname: {:?}", msg.nickname);

    // Fetch sender public key
    let recipient_key = match api.lookup_pubkey(&msg.from).await {
        Ok(key) => key,
        Err(error) => {
            eprintln!("Could not fetch public key for {}: {error}", &msg.from);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Decrypt and decode
    match api.decrypt_and_decode_incoming_message(&msg, &recipient_key) {
        Ok(message) => {
            println!("Decrypted message: {message:?}");
            StatusCode::OK
        }
        Err(error) => {
            eprintln!("Could not decrypt box: {error}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
