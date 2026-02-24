//! Typing indicator message related types.

use thiserror::Error;

/// A typing indicator status indicates when a contact is typing or stopped typing.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TypingStatus {
    /// The contact is not typing
    NotTyping,
    /// The contact is currently typing
    Typing,
}

impl TypingStatus {
    /// Return whether or not the user is typing.
    #[must_use]
    pub fn is_typing(self) -> bool {
        self == TypingStatus::Typing
    }
}

impl From<TypingStatus> for u8 {
    fn from(val: TypingStatus) -> Self {
        match val {
            TypingStatus::NotTyping => 0x00,
            TypingStatus::Typing => 0x01,
        }
    }
}

impl From<TypingStatus> for bool {
    fn from(val: TypingStatus) -> Self {
        val.is_typing()
    }
}

impl From<bool> for TypingStatus {
    fn from(val: bool) -> Self {
        if val {
            TypingStatus::Typing
        } else {
            TypingStatus::NotTyping
        }
    }
}

impl TryFrom<u8> for TypingStatus {
    type Error = InvalidTypingIndicatorValue;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(TypingStatus::NotTyping),
            0x01 => Ok(TypingStatus::Typing),
            _ => Err(InvalidTypingIndicatorValue(value)),
        }
    }
}

/// Errors when parsing a typing indicator message.
#[derive(Debug, PartialEq, Clone, Error)]
pub enum TypingIndicatorMessageParseError {
    /// Invalid message length (must be exactly 1 byte)
    #[error("invalid message byte length (must be 1 byte): {0}")]
    InvalidLength(usize),
    /// Invalid value (must be 0 or 1)
    #[error("invalid typing indicator value: {0}")]
    InvalidValue(#[from] InvalidTypingIndicatorValue),
}

/// An invalid typing indicator value was encountered.
#[derive(Debug, PartialEq, Clone, Error)]
#[error("invalid typing indicator value: {0} (must be 0 or 1)")]
pub struct InvalidTypingIndicatorValue(pub u8);

/// A typing indicator message.
///
/// Contains a single byte indicating whether the contact is typing or not.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TypingIndicatorMessage {
    /// The typing indicator status
    pub status: TypingStatus,
}

impl TypingIndicatorMessage {
    /// Create a new [`TypingIndicatorMessage`].
    #[must_use]
    pub const fn new(indicator: TypingStatus) -> Self {
        Self { status: indicator }
    }

    /// Encode this message to its wire-format bytes.
    ///
    /// Returns a single byte: 1 if typing, 0 if stopped typing.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        vec![u8::from(self.status)]
    }

    /// Decode a typing indicator message from raw bytes.
    ///
    /// The first (and only) byte must be 0 (stopped typing) or 1 (typing).
    pub fn decode(bytes: &[u8]) -> Result<Self, TypingIndicatorMessageParseError> {
        match bytes {
            &[byte] => Ok(Self {
                status: TypingStatus::try_from(byte)?,
            }),
            _ => Err(TypingIndicatorMessageParseError::InvalidLength(bytes.len())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod typing_indicator {
        use super::*;

        #[test]
        fn to_u8() {
            assert_eq!(u8::from(TypingStatus::NotTyping), 0x00);
            assert_eq!(u8::from(TypingStatus::Typing), 0x01);
        }

        #[test]
        fn try_from_u8() {
            assert_eq!(TypingStatus::try_from(0x00), Ok(TypingStatus::NotTyping));
            assert_eq!(TypingStatus::try_from(0x01), Ok(TypingStatus::Typing));
            assert_eq!(
                TypingStatus::try_from(0x02),
                Err(InvalidTypingIndicatorValue(0x02))
            );
            assert_eq!(
                TypingStatus::try_from(0xff),
                Err(InvalidTypingIndicatorValue(0xff))
            );
        }

        #[test]
        fn round_trip() {
            let typing = TypingStatus::Typing;
            assert_eq!(TypingStatus::try_from(u8::from(typing)).unwrap(), typing);

            let stopped = TypingStatus::NotTyping;
            assert_eq!(TypingStatus::try_from(u8::from(stopped)).unwrap(), stopped);
        }
    }

    mod typing_indicator_message {
        use super::*;

        #[test]
        fn new_typing() {
            let msg = TypingIndicatorMessage::new(TypingStatus::Typing);
            assert_eq!(msg.status, TypingStatus::Typing);
        }

        #[test]
        fn new_stopped_typing() {
            let msg = TypingIndicatorMessage::new(TypingStatus::NotTyping);
            assert_eq!(msg.status, TypingStatus::NotTyping);
        }

        #[test]
        fn encode_typing() {
            let msg = TypingIndicatorMessage::new(TypingStatus::Typing);
            let bytes = msg.encode();
            assert_eq!(bytes, vec![0x01]);
        }

        #[test]
        fn encode_stopped_typing() {
            let msg = TypingIndicatorMessage::new(TypingStatus::NotTyping);
            let bytes = msg.encode();
            assert_eq!(bytes, vec![0x00]);
        }

        #[test]
        fn decode_typing() {
            let msg = TypingIndicatorMessage::decode(&[0x01]).expect("valid bytes should decode");
            assert_eq!(msg.status, TypingStatus::Typing);
        }

        #[test]
        fn decode_stopped_typing() {
            let msg = TypingIndicatorMessage::decode(&[0x00]).expect("valid bytes should decode");
            assert_eq!(msg.status, TypingStatus::NotTyping);
        }

        #[test]
        fn decode_empty() {
            let err = TypingIndicatorMessage::decode(&[]).unwrap_err();
            assert_eq!(err, TypingIndicatorMessageParseError::InvalidLength(0));
        }

        #[test]
        fn decode_too_long() {
            let err = TypingIndicatorMessage::decode(&[0x01, 0x02]).unwrap_err();
            assert_eq!(err, TypingIndicatorMessageParseError::InvalidLength(2));
        }

        #[test]
        fn decode_invalid_value() {
            let err = TypingIndicatorMessage::decode(&[0x02]).unwrap_err();
            assert_eq!(
                err,
                TypingIndicatorMessageParseError::InvalidValue(InvalidTypingIndicatorValue(0x02))
            );
        }

        #[test]
        fn round_trip_typing() {
            let original = TypingIndicatorMessage::new(TypingStatus::Typing);
            let decoded = TypingIndicatorMessage::decode(&original.encode())
                .expect("round-trip decode should succeed");
            assert_eq!(decoded, original);
        }

        #[test]
        fn round_trip_stopped_typing() {
            let original = TypingIndicatorMessage::new(TypingStatus::NotTyping);
            let decoded = TypingIndicatorMessage::decode(&original.encode())
                .expect("round-trip decode should succeed");
            assert_eq!(decoded, original);
        }
    }
}
