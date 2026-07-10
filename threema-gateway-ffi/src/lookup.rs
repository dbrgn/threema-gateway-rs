//! Directory lookups: criteria and capability results.

use threema_gateway as lib;

/// Different ways to look up a Threema ID in the directory.
#[derive(uniffi::Enum)]
#[expect(missing_docs, reason = "UniFFI enum variant fields")]
pub enum LookupCriterion {
    /// The phone number in E.164 format, without the leading `+`.
    Phone { phone: String },
    /// HMAC-SHA256 hash of the E.164 phone number.
    PhoneHash { phone_hash: String },
    /// The e-mail address.
    Email { email: String },
    /// HMAC-SHA256 hash of the lowercased, trimmed e-mail address.
    EmailHash { email_hash: String },
}

impl From<LookupCriterion> for lib::LookupCriterion {
    fn from(val: LookupCriterion) -> Self {
        match val {
            LookupCriterion::Phone { phone } => lib::LookupCriterion::Phone(phone),
            LookupCriterion::PhoneHash { phone_hash } => {
                lib::LookupCriterion::PhoneHash(phone_hash)
            }
            LookupCriterion::Email { email } => lib::LookupCriterion::Email(email),
            LookupCriterion::EmailHash { email_hash } => {
                lib::LookupCriterion::EmailHash(email_hash)
            }
        }
    }
}

/// Capabilities of a Threema ID.
#[derive(uniffi::Record)]
#[expect(clippy::struct_excessive_bools, reason = "Matches upstream type")]
pub struct Capabilities {
    /// Whether the ID can receive text messages.
    pub text: bool,
    /// Whether the ID can receive image messages.
    pub image: bool,
    /// Whether the ID can receive video messages.
    pub video: bool,
    /// Whether the ID can receive audio messages.
    pub audio: bool,
    /// Whether the ID can receive file messages.
    pub file: bool,
    /// List of other capabilities this ID has.
    pub other: Vec<String>,
}

impl From<lib::Capabilities> for Capabilities {
    fn from(val: lib::Capabilities) -> Self {
        // Destructured so a new field added upstream fails to compile here, rather than being
        // silently dropped on the foreign side.
        let lib::Capabilities {
            text,
            image,
            video,
            audio,
            file,
            other,
        } = val;
        Self {
            text,
            image,
            video,
            audio,
            file,
            other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod from_lookup_criterion {
        use super::*;

        #[test]
        fn phone() {
            let ffi = LookupCriterion::Phone {
                phone: "41791234567".to_owned(),
            };
            assert_eq!(
                lib::LookupCriterion::from(ffi),
                lib::LookupCriterion::Phone("41791234567".to_owned())
            );
        }

        #[test]
        fn phone_hash() {
            let hex = "a".repeat(64);
            let ffi = LookupCriterion::PhoneHash {
                phone_hash: hex.clone(),
            };
            assert_eq!(
                lib::LookupCriterion::from(ffi),
                lib::LookupCriterion::PhoneHash(hex)
            );
        }

        #[test]
        fn email() {
            let ffi = LookupCriterion::Email {
                email: "user@example.com".to_owned(),
            };
            assert_eq!(
                lib::LookupCriterion::from(ffi),
                lib::LookupCriterion::Email("user@example.com".to_owned())
            );
        }

        #[test]
        fn email_hash() {
            let hex = "b".repeat(64);
            let ffi = LookupCriterion::EmailHash {
                email_hash: hex.clone(),
            };
            assert_eq!(
                lib::LookupCriterion::from(ffi),
                lib::LookupCriterion::EmailHash(hex)
            );
        }
    }

    mod from_capabilities {
        use super::*;

        #[test]
        fn all_fields_preserved() {
            let upstream = lib::Capabilities {
                text: true,
                image: false,
                video: true,
                audio: false,
                file: true,
                other: vec!["call".to_owned(), "video-call".to_owned()],
            };
            let ffi = Capabilities::from(upstream);
            assert!(ffi.text);
            assert!(!ffi.image);
            assert!(ffi.video);
            assert!(!ffi.audio);
            assert!(ffi.file);
            assert_eq!(ffi.other, vec!["call".to_owned(), "video-call".to_owned()]);
        }

        #[test]
        fn empty_other_preserved() {
            let upstream = lib::Capabilities {
                text: false,
                image: false,
                video: false,
                audio: false,
                file: false,
                other: Vec::new(),
            };
            let ffi = Capabilities::from(upstream);
            assert!(ffi.other.is_empty());
        }
    }
}
