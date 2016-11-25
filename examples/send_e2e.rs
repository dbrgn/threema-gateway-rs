extern crate docopt;
extern crate threema_gateway;

use docopt::Docopt;
use threema_gateway::crypto::encrypt;
use threema_gateway::connection::send_e2e;


const USAGE: &'static str = "
Usage: send_e2e [options] <from> <to> <secret> <text>...

Options:
    -h, --help    Show this help
";


fn main() {
    let args = Docopt::new(USAGE)
                      .and_then(|docopt| docopt.parse())
                      .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let from = args.get_str("<from>");
    let to = args.get_str("<to>");
    let secret = args.get_str("<secret>");
    let text = args.get_vec("<text>").join(" ");

    // Encrypt and send
    let (ciphertext, nonce) = encrypt(&text);
    let msg_id = send_e2e(&from, &to, &secret, &nonce, &ciphertext);

    println!("Sent. Message id is {}.", &msg_id);
}
