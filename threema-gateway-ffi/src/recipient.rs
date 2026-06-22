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
