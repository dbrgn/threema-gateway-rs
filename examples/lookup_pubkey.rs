extern crate docopt;
extern crate threema_gateway;

use docopt::Docopt;
use threema_gateway::{ApiBuilder};


const USAGE: &'static str = "
Usage: send_e2e [options] <our_id> <secret> <their_id>

Options:
    -h, --help    Show this help
";


fn main() {
    let args = Docopt::new(USAGE)
                      .and_then(|docopt| docopt.parse())
                      .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let our_id = args.get_str("<our_id>");
    let their_id = args.get_str("<their_id>");
    let secret = args.get_str("<secret>");

    // Fetch public key
    let api = ApiBuilder::new(our_id, secret).into_simple();
    let pubkey = api.lookup_pubkey(their_id);

    // Show result
    match pubkey {
        Ok(pk) => println!("Public key for {} is {}.", their_id, pk),
        Err(e) => println!("Could not fetch public key: {:?}", e),
    }
}
