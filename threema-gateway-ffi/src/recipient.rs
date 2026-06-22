//! Message recipient and their public key.

use threema_gateway as lib;

/// Different ways to specify a message recipient in basic mode.
#[derive(uniffi::Enum)]
#[expect(missing_docs, reason = "UniFFI enum variant fields")]
pub enum Recipient {
    /// Recipient identity (8 characters).
    Id { id: String },
    /// Recipient phone number (E.164), without leading +.
    Phone { phone: String },
    /// Recipient e-mail address.
    Email { email: String },
}

impl TryFrom<Recipient> for lib::Recipient<'static> {
    type Error = lib::ThreemaIdError;

    fn try_from(val: Recipient) -> Result<Self, Self::Error> {
        Ok(match val {
            Recipient::Id { id } => lib::Recipient::new_id(id.parse()?),
            Recipient::Phone { phone } => lib::Recipient::new_phone(phone),
            Recipient::Email { email } => lib::Recipient::new_email(email),
        })
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

    mod try_from_recipient {
        use super::*;

        #[test]
        fn id_valid() {
            let ffi = Recipient::Id {
                id: "ECHOECHO".to_owned(),
            };
            let result = lib::Recipient::try_from(ffi).expect("ECHOECHO is a valid Threema ID");
            let lib::Recipient::Id(id) = result else {
                unreachable!("expected Id variant")
            };
            assert_eq!(id.as_str(), "ECHOECHO");
        }

        #[test]
        fn id_gateway() {
            let ffi = Recipient::Id {
                id: "*MYGATWY".to_owned(),
            };
            let result = lib::Recipient::try_from(ffi).expect("gateway IDs start with *");
            assert!(matches!(result, lib::Recipient::Id(_)));
        }

        #[test]
        fn id_too_short() {
            let ffi = Recipient::Id {
                id: "SHORT".to_owned(),
            };
            let result = lib::Recipient::try_from(ffi);
            assert!(matches!(result, Err(lib::ThreemaIdError::InvalidLength)));
        }

        #[test]
        fn id_too_long() {
            let ffi = Recipient::Id {
                id: "MUCHTOOLONG".to_owned(),
            };
            let result = lib::Recipient::try_from(ffi);
            assert!(matches!(result, Err(lib::ThreemaIdError::InvalidLength)));
        }

        #[test]
        fn id_invalid_chars() {
            let ffi = Recipient::Id {
                id: "echoecho".to_owned(),
            };
            let result = lib::Recipient::try_from(ffi);
            assert!(matches!(result, Err(lib::ThreemaIdError::InvalidSymbols)));
        }

        #[test]
        fn phone_passes_through_unchanged() {
            let ffi = Recipient::Phone {
                phone: "41791234567".to_owned(),
            };
            let result = lib::Recipient::try_from(ffi).expect("phone is not validated");
            let lib::Recipient::Phone(phone) = result else {
                unreachable!("expected Phone variant")
            };
            assert_eq!(phone.as_ref(), "41791234567");
        }

        #[test]
        fn email_passes_through_unchanged() {
            let ffi = Recipient::Email {
                email: "user@example.com".to_owned(),
            };
            let result = lib::Recipient::try_from(ffi).expect("email is not validated");
            let lib::Recipient::Email(email) = result else {
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
