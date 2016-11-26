# Rust SDK for Threema Gateway

This is a work-in-progress implementation of a Threema Gateway client library
in Rust.


## Usage

Take a look at the examples in the `examples/` directory to see how they're
implemented.

Lookup public key:

    cargo run --example lookup_pubkey -- <our_id> <secret> <their_id>

Send simple transport-encrypted encrypted message:

    cargo run --example send_simple -- <from> id <to-id> <secret> <text>...
    cargo run --example send_simple -- <from> email <to-email> <secret> <text>...
    cargo run --example send_simple -- <from> phone <to-phone> <secret> <text>...

Send e2e encrypted message:

    cargo run --example send_e2e -- <from> <to> <secret> <text>...


## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT) at your option.


### Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
