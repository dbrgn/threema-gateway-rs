# Rust SDK for Threema Gateway

[![Travis CI][travis-ci-badge]][travis-ci]
[![Crates.io][crates-io-badge]][crates-io]
[![Rust][rust-badge]][github]

This is a work-in-progress implementation of a Threema Gateway client library
in Rust.

[Docs](https://dbrgn.github.io/threema-gateway-rs/threema_gateway/index.html)


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

<!-- Badges -->
[travis-ci]: https://travis-ci.org/dbrgn/threema-gateway-rs
[travis-ci-badge]: https://img.shields.io/travis/dbrgn/threema-gateway-rs.svg?maxAge=3600
[crates-io]: https://crates.io/crates/threema-gateway
[crates-io-badge]: https://img.shields.io/crates/v/threema-gateway.svg?maxAge=3600
[github]: https://github.com/dbrgn/threema-gateway-rs
[rust-badge]: https://img.shields.io/badge/rust-1.9%2B-blue.svg?maxAge=3600
