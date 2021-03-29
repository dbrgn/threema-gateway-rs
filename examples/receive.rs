use data_encoding::HEXLOWER_PERMISSIVE;
use docopt::Docopt;
use threema_gateway::{ApiBuilder, IncomingMessage, SecretKey};

const USAGE: &str = "
Usage: receive [options] <secret> <request-body> <our-id> <our-private-key>

Options:
    -h, --help    Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let secret = args.get_str("<secret>");
    let request_body = args.get_str("<request-body>");
    let our_id = args.get_str("<our-id>");
    let our_private_key = HEXLOWER_PERMISSIVE
        .decode(args.get_str("<our-private-key>").as_bytes())
        .ok()
        .and_then(|bytes| SecretKey::from_slice(&bytes))
        .unwrap_or_else(|| {
            eprintln!("Invalid private key");
            std::process::exit(1);
        });

    // Parse request body
    let msg = IncomingMessage::from_urlencoded_bytes(request_body).unwrap_or_else(|e| {
        eprintln!("Could not decode incoming message: {}", e);
        std::process::exit(1);
    });

    println!("Parsed message from request");
    println!("  From: {}", msg.from);
    println!("  To: {}", msg.to);
    println!("  Message ID: {}", msg.message_id);
    println!("  Timestamp: {}", msg.date);
    println!("  Sender nickname: {:?}", msg.nickname);

    // Fetch sender public key
    let api = ApiBuilder::new(our_id, secret).into_simple();
    let pubkey = api.lookup_pubkey(&msg.from).await.unwrap_or_else(|e| {
        eprintln!("Could not fetch public key for {}: {}", &msg.from, e);
        std::process::exit(1);
    });

    // Decrypt
    let data = msg
        .decrypt_box(&pubkey, &our_private_key)
        .unwrap_or_else(|e| {
            println!("Could not decrypt box: {}", e);
            std::process::exit(1);
        });

    // Show result
    println!("Decrypted box: {:?}", data);
}
