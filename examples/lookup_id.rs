use std::process;

use docopt::Docopt;
use threema_gateway::{ApiBuilder, LookupCriterion};

const USAGE: &str = "
Usage: lookup_id [options] by_phone <from> <secret> <phone>
       lookup_id [options] by_phone_hash <from> <secret> <phone-hash>
       lookup_id [options] by_email <from> <secret> <email>
       lookup_id [options] by_email_hash <from> <secret> <email-hash>

Options:
    -h, --help    Show this help
";

fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|docopt| docopt.parse())
        .unwrap_or_else(|e| e.exit());

    // Command line arguments
    let from = args.get_str("<from>");
    let secret = args.get_str("<secret>");
    let criterion = if args.get_bool("by_phone") {
        LookupCriterion::Phone(args.get_str("<phone>").to_string())
    } else if args.get_bool("by_phone_hash") {
        LookupCriterion::PhoneHash(args.get_str("<phone-hash>").to_string())
    } else if args.get_bool("by_email") {
        LookupCriterion::Email(args.get_str("<email>").to_string())
    } else if args.get_bool("by_email_hash") {
        LookupCriterion::EmailHash(args.get_str("<email-hash>").to_string())
    } else {
        panic!("Invalid command");
    };

    println!(
        "Looking up id by {}...",
        match criterion {
            LookupCriterion::Phone(_) => "phone",
            LookupCriterion::PhoneHash(_) => "phone hash",
            LookupCriterion::Email(_) => "email",
            LookupCriterion::EmailHash(_) => "email hash",
        }
    );

    // Look up ID
    let api = ApiBuilder::new(from, secret).into_simple();
    match api.lookup_id(&criterion) {
        Err(e) => {
            println!("Could not look up id: {:?}", e);
            process::exit(1);
        }
        Ok(id) => println!("The id is {}", id),
    }
}
