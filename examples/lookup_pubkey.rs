use docopt::Docopt;
use threema_gateway::ApiBuilder;

const USAGE: &str = "
Usage: lookup_pubkey [options] <our_id> <secret> <their_id>

Options:
    -h, --help    Show this help
";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let our_id = args.get_str("<our_id>");
    let their_id = args.get_str("<their_id>");
    let secret = args.get_str("<secret>");

    // Fetch recipient public key
    let api = ApiBuilder::new(our_id, secret).into_simple();
    let recipient_key = api.lookup_pubkey(their_id).await;

    // Show result
    match recipient_key {
        Ok(key) => println!("Public key for {} is {}.", their_id, key.to_hex_string()),
        Err(e) => println!("Could not fetch public key: {}", e),
    }
}
