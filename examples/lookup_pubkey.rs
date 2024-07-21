use docopt::Docopt;
use threema_gateway::{ApiBuilder, PublicKeyCache};

const USAGE: &str = "
Usage: lookup_pubkey [--with-cache] <our_id> <secret> <their_id>

Options:
    --with-cache  Simulate a cache
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
    let simulate_cache = args.get_bool("--with-cache");

    // Fetch recipient public key
    let api = ApiBuilder::new(our_id, secret).into_simple();
    let pubkey = if simulate_cache {
        let cache = SimulatedCache;
        api.lookup_pubkey_with_cache(their_id, &cache)
            .await
            .unwrap_or_else(|e| {
                println!("Could not fetch public key: {}", e);
                std::process::exit(1);
            })
    } else {
        api.lookup_pubkey(their_id).await.unwrap_or_else(|e| {
            println!("Could not fetch and cache public key: {}", e);
            std::process::exit(1);
        })
    };

    // Show result
    println!("Public key for {} is {}.", their_id, pubkey.to_hex_string());
}

struct SimulatedCache;

impl PublicKeyCache for SimulatedCache {
    type Error = std::io::Error;

    async fn store(
        &self,
        identity: &str,
        _key: &threema_gateway::RecipientKey,
    ) -> Result<(), Self::Error> {
        println!("[cache] Storing public key for identity {identity}");
        Ok(())
    }

    async fn load(
        &self,
        _identity: &str,
    ) -> Result<Option<threema_gateway::RecipientKey>, Self::Error> {
        unimplemented!("Not implemented in this example")
    }
}
