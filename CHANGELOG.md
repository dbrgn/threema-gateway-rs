# Changelog

This project follows semantic versioning.

Possible log types:

- `[added]` for new features.
- `[changed]` for changes in existing functionality.
- `[deprecated]` for once-stable features removed in upcoming releases.
- `[removed]` for deprecated features removed in this release.
- `[fixed]` for any bug fixes.
- `[security]` to invite users to upgrade in case of vulnerabilities.


### Unreleased

- [added] Allow specifying `RenderingType` for file messages
- [changed] The API for `E2eApi::encrypt_file_msg` has changed
- [changed] You now need to import `std::str::FromStr` to directly access
  `BlobId::from_str` or `RecipientKey::from_str`

### v0.12.1 (2019-10-22)

- Maintenance release

### v0.12.0 (2019-09-19)

- [added] Blob upload: Add support for `persist` flag (#25) 
- [fixed] Fix documentation for BlobId

### v0.11.0 (2019-09-12)

- [added] Re-export `mime::Mime`
- [added] Re-export `sodiumoxide::crypto::secretbox::Key`
- [added] Re-export `sodiumoxide::crypto::box_::{PublicKey, SecretKey}`

### v0.10.0 (2019-08-05)

- [changed] Upgrade docopt to 1.1
- [changed] Stop tracking a certain minimal supported Rust version

### v0.9.1 (2019-04-08)

- [fixed] Pinned docopt to 1.0.x

### v0.9.0 (2019-01-01)

- [changed] Upgrade sodiumoxide to 0.2
- [changed] Upgrade reqwest to 0.9
- [changed] Require Rust 1.31+ (Rust 2018)

### v0.8.0 (2018-04-23)

- [added] Add `ApiBuilder::with_custom_endpoint` method
- [changed] Require Rust 1.21+
- [changed] Constructors of `SimpleApi` and `E2eApi` are now private, use the
  `ApiBuilder` instead
- [changed] Upgrade sodiumoxide dependency to 0.0.16
- [changed] Upgrade reqwest dependency to 0.8
- [changed] Upgrade log dependency to 0.4
- [changed] Upgrade data-encoding dependency to 2.1

### v0.7.1 (2017-08-28)

- [changed] Upgrade data-encoding dependency to 2.0.0-rc.2
- [changed] Upgrade mime_guess dependency to 2.0.0-alpha.2

### v0.7.0 (2017-07-17)

- [changed] Update reqwest dependency to 0.7
- [changed] Update mime dependency to 0.3
- [changed] Require Rust 1.18+

### v0.6.0 (2017-05-29)

- [changed] Upgrade serde to 1.0.0

### v0.5.0 (2017-04-20)

- [changed] Require Rust 1.15+
- [added] Implement `lookup_credits` (#8)
- [added] Implement `lookup_capabilities` (#9)
- [added] Implement blob uploading (#11)
- [added] Implement encrypting of e2e text, image and file messages (#11)

### v0.4.1 (2017-04-12)

- [added] Add `as_bytes` and `Into<String>` to `RecipientKey` (#7)

### v0.4.0 (2017-04-10)

- [changed] Revamped and simplified entire API, it now uses a more
  object-oriented approach (#6)

### v0.3.2 (2017-04-06)

- [fixed] Fix bad API URL
- [changed] Update reqwest dependency to 0.5

### v0.3.1 (2017-04-04)

- [added] Add debug logging to lookups

### v0.3.0 (2017-03-22)

- [changed] Upgrade some dependencies
- [changed] Move from hyper to reqwest
- [changed] Require Rust 1.13+

### v0.2.0 (2016-12-15)

- [added] Implement Threema ID lookups

### v0.1.0 (2016-12-15)

- Initial release
