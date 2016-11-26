extern crate docopt;
extern crate threema_gateway;

use std::borrow::Cow;

use docopt::Docopt;
use threema_gateway::connection::{send_simple, Recipient};


const USAGE: &'static str = "
Usage: send_simple [options] <from> id <to-id> <secret> <text>...
       send_simple [options] <from> email <to-email> <secret> <text>...
       send_simple [options] <from> phone <to-phone> <secret> <text>...

Options:
    -h, --help    Show this help
";


fn main() {
    let args = Docopt::new(USAGE)
                      .and_then(|docopt| docopt.parse())
                      .unwrap_or_else(|e| e.exit());
    println!("{:?}", args);

    // Command line arguments
    let from = args.get_str("<from>");
    let secret = args.get_str("<secret>");
    let text = args.get_vec("<text>").join(" ");

    // Send without encrypting
    let recipient = if args.get_bool("id") {
        Recipient::Id(Cow::from(args.get_str("<to-id>")))
    } else if args.get_bool("email") {
        Recipient::Email(Cow::from(args.get_str("<to-email>")))
    } else if args.get_bool("phone") {
        Recipient::Phone(Cow::from(args.get_str("<to-phone>")))
    } else {
        unreachable!();
    };

    let msg_id = send_simple(&from, &recipient, &secret, &text);
    match msg_id {
        Ok(id) => println!("Sent. Message id is {}.", id),
        Err(e) => println!("Could not send message: {:?}", e),
    }
}
