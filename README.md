# Rust SDK for Threema Gateway

[![GitHub CI][github-actions-badge]][github-actions]
[![Crates.io Version][crates-io-badge]][crates-io]
[![Crates.io Downloads][crates-io-download-badge]][crates-io-download]

This is a mostly-complete implementation of an asynchronous Threema Gateway
client library in Rust. For implementation status, see feature list below.

[Docs](https://docs.rs/threema-gateway)


## Features

**Sending**

- [x] Send simple messages
- [x] Send end-to-end encrypted messages

**Encrypting**

- [x] Encrypt raw bytes
- [x] Encrypt text messages
- [x] Encrypt image messages
- [x] Encrypt file messages
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

- [x] Decode incoming request body
- [x] Verify MAC of incoming message
- [x] Decrypt incoming message
- [ ] Decode incoming message

**Files**

- [x] Upload files
- [x] Download files


## Usage

Take a look at the examples in the `examples/` directory to see how they're
implemented.

Generate a new keypair:

    cargo run --example generate_keypair

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

Decode and decrypt an incoming message payload:

    cargo run --example receive -- <our-id> <secret> <private-key> <request-body>

Download a blob:

    cargo run --example download_blob -- <our-id> <secret> <private-key> <blob-id>


## Cargo Features

This library offers the following optional features:

- `receive`: Add support for processing incoming messages. Enabled by default.


## Rust Version Requirements (MSRV)

This library generally tracks the latest stable Rust version but tries to
guarantee backwards compatibility with older stable versions as much as
possible. However, in many cases transitive dependencies make guaranteeing a
minimal supported Rust version impossible (see [this
discussion](https://users.rust-lang.org/t/rust-version-requirement-change-as-semver-breaking-or-not/20980/25)).


## TLS

This library uses [rustls](https://github.com/ctz/rustls) with native
(system-provided) root certificates to establish a TLS connection.


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
[github-actions]: https://github.com/dbrgn/threema-gateway-rs/actions?query=branch%3Amaster
[github-actions-badge]: https://github.com/dbrgn/threema-gateway-rs/workflows/CI/badge.svg
[crates-io]: https://crates.io/crates/threema-gateway
[crates-io-badge]: https://img.shields.io/crates/v/threema-gateway.svg?maxAge=3600
[crates-io-download]: https://crates.io/crates/threema-gateway
[crates-io-download-badge]: https://img.shields.io/crates/d/threema-gateway.svg?maxAge=3600
