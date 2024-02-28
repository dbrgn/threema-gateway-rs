use data_encoding::HEXLOWER_PERMISSIVE;
use docopt::Docopt;
use threema_gateway::{ApiBuilder, SecretKey};

const USAGE: &str = "
Usage: receive [options] <our-id> <secret> <private-key> <request-body>

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
    let request_body = args.get_str("<request-body>");

    // Create E2eApi instance
    let api = ApiBuilder::new(our_id, secret)
        .with_private_key(private_key)
        .into_e2e()
        .unwrap();

    // Parse request body
    let msg = api
        .decode_incoming_message(request_body)
        .unwrap_or_else(|e| {
            eprintln!("Could not decode incoming message: {}", e);
            std::process::exit(1);
        });

    println!("Parsed and validated message from request:");
    println!("  From: {}", msg.from);
    println!("  To: {}", msg.to);
    println!("  Message ID: {}", msg.message_id);
    println!("  Timestamp: {}", msg.date);
    println!("  Sender nickname: {:?}", msg.nickname);

    // Fetch sender public key
    let recipient_key = api.lookup_pubkey(&msg.from).await.unwrap_or_else(|e| {
        eprintln!("Could not fetch public key for {}: {}", &msg.from, e);
        std::process::exit(1);
    });

    // Decrypt
    let data = api
        .decrypt_incoming_message(&msg, &recipient_key)
        .unwrap_or_else(|e| {
            println!("Could not decrypt box: {}", e);
            std::process::exit(1);
        });

    // Show result
    println!("Decrypted box: {:?}", data);
}
