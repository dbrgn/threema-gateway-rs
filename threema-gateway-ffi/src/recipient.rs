//! Message recipient and their public key.

use std::sync::Arc;

use threema_gateway as lib;

use crate::threema_id::ThreemaId;

/// Different ways to specify a message recipient in basic mode.
#[derive(uniffi::Enum)]
#[expect(missing_docs, reason = "UniFFI enum variant fields")]
pub enum Recipient {
    /// Recipient identity.
    Id { id: Arc<ThreemaId> },
    /// Recipient phone number (E.164), without leading +.
    Phone { phone: String },
    /// Recipient e-mail address.
    Email { email: String },
}

impl From<Recipient> for lib::Recipient<'static> {
    fn from(val: Recipient) -> Self {
        match val {
            Recipient::Id { id } => lib::Recipient::new_id(id.inner),
            Recipient::Phone { phone } => lib::Recipient::new_phone(phone),
            Recipient::Email { email } => lib::Recipient::new_email(email),
        }
    }
}

/// A Threema ID's public key (32 bytes).
#[derive(uniffi::Record)]
pub struct RecipientKey {
    /// The raw public key bytes.
    pub bytes: Vec<u8>,
}

impl From<lib::RecipientKey> for RecipientKey {
    fn from(val: lib::RecipientKey) -> Self {
        Self {
            bytes: val.as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod from_recipient {
        use super::*;

        #[test]
        fn id() {
            let threema_id = ThreemaId::new("ECHOECHO").expect("valid Threema ID");
            let ffi = Recipient::Id { id: threema_id };
            let lib::Recipient::Id(id) = lib::Recipient::from(ffi) else {
                unreachable!("expected Id variant")
            };
            assert_eq!(id.as_str(), "ECHOECHO");
        }

        #[test]
        fn phone_passes_through_unchanged() {
            let ffi = Recipient::Phone {
                phone: "41791234567".to_owned(),
            };
            let lib::Recipient::Phone(phone) = lib::Recipient::from(ffi) else {
                unreachable!("expected Phone variant")
            };
            assert_eq!(phone.as_ref(), "41791234567");
        }

        #[test]
        fn email_passes_through_unchanged() {
            let ffi = Recipient::Email {
                email: "user@example.com".to_owned(),
            };
            let lib::Recipient::Email(email) = lib::Recipient::from(ffi) else {
                unreachable!("expected Email variant")
            };
            assert_eq!(email.as_ref(), "user@example.com");
        }
    }

    mod from_recipient_key {
        use super::*;

        #[test]
        fn bytes_round_trip() {
            let raw = [0xAB_u8; 32];
            let lib_key = lib::RecipientKey::from(raw);
            let ffi_key = RecipientKey::from(lib_key);
            assert_eq!(ffi_key.bytes.as_slice(), raw.as_slice());
        }

        #[test]
        fn bytes_length_is_32() {
            let lib_key = lib::RecipientKey::from([0_u8; 32]);
            let ffi_key = RecipientKey::from(lib_key);
            assert_eq!(ffi_key.bytes.len(), 32);
        }
    }
}
