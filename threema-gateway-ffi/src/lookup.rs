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
        Self {
            text: val.text,
            image: val.image,
            video: val.video,
            audio: val.audio,
            file: val.file,
            other: val.other,
        }
    }
}
