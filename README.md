# Rust SDK for Threema Gateway

[![Travis CI][travis-ci-badge]][travis-ci]
[![Crates.io Version][crates-io-badge]][crates-io]
[![Crates.io Downloads][crates-io-download-badge]][crates-io-download]
[![Rust][rust-badge]][github]

This is a work-in-progress implementation of a Threema Gateway client library
in Rust.

Not everything is implemented yet, but sending simple and end-to-end encrypted
messages works.

[Docs](https://docs.rs/threema-gateway)


## Features

**Sending**

- [x] Send simple messages
- [x] Send end-to-end encrypted messages

**Encrypting**

- [x] Encrypt raw bytes
- [x] Encrypt text messages
- [x] Encrypt image messages
- [ ] Encrypt file messages
- [ ] Encrypt delivery receipt messages

**Lookup**

- [x] Look up ID by phone number
- [x] Look up ID by e-mail
- [x] Look up ID by phone number hash
- [x] Look up ID by e-mail hash
- [x] Look up capabilities by ID
- [x] Look up public key by ID
- [x] Look up remaining credits

**Receiving**

- [ ] Verify MAC of incoming message
- [ ] Decrypt incoming message

**Files**

- [x] Upload files
- [ ] Download files


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

    cargo run --example send_e2e_text -- <from> <to> <secret> <private-key> <text>...

Look up Threema ID by phone:

    cargo run --example lookup_id -- by_phone <from> <secret> 41791234567

Look up Threema ID by email hash:

    cargo run --example lookup_id -- by_email_hash <from> <secret> 1ea093239cc5f0e1b6ec81b866265b921f26dc4033025410063309f4d1a8ee2c


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
[travis-ci-badge]: https://img.shields.io/travis/dbrgn/threema-gateway-rs.svg?maxAge=300
[crates-io]: https://crates.io/crates/threema-gateway
[crates-io-badge]: https://img.shields.io/crates/v/threema-gateway.svg?maxAge=3600
[crates-io-download]: https://crates.io/crates/threema-gateway
[crates-io-download-badge]: https://img.shields.io/crates/d/threema-gateway.svg?maxAge=3600
[github]: https://github.com/dbrgn/threema-gateway-rs
[rust-badge]: https://img.shields.io/badge/rust-1.13%2B-blue.svg?maxAge=3600
