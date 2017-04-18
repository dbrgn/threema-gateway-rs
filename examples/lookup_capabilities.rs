extern crate docopt;
extern crate threema_gateway;

use docopt::Docopt;
use threema_gateway::{ApiBuilder};


const USAGE: &'static str = "
Usage: lookup_capabilities [options] <our_id> <secret> <their_id>

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
    let pubkey = api.lookup_capabilities(their_id);

    // Show result
    match pubkey {
        Ok(cap) => println!("Capabilities for {}: {}", their_id, cap),
        Err(e) => println!("Could not lookup capabilities: {}", e),
    }
}
