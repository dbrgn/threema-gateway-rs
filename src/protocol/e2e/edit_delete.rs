//! Edit and delete message related types.

use prost::Message as _;
use thiserror::Error;

use crate::{protobuf, protocol::MessageId};

/// Errors when parsing an edit message.
#[derive(Debug, PartialEq, Clone, Error)]
pub enum EditMessageParseError {
    /// Protobuf decode error
    #[error("protobuf decode error: {0}")]
    Protobuf(String),
}

/// Errors when parsing a delete message.
#[derive(Debug, PartialEq, Clone, Error)]
pub enum DeleteMessageParseError {
    /// Protobuf decode error
    #[error("protobuf decode error: {0}")]
    Protobuf(String),
}

/// An edit message.
///
/// Contains the message ID of the message to be edited and the replacement text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditMessage {
    /// The message ID of the message to be edited
    pub message_id: MessageId,
    /// The replacement text (or caption)
    pub text: String,
}

impl EditMessage {
    /// Create a new [`EditMessage`].
    #[must_use]
    pub fn new(message_id: MessageId, text: String) -> Self {
        Self { message_id, text }
    }

    /// Encode this message to its wire-format bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let proto_message = protobuf::csp_e2e::EditMessage {
            message_id: self.message_id.as_u64(),
            text: self.text.clone(),
        };
        let mut buf = Vec::with_capacity(proto_message.encoded_len());
        proto_message
            .encode(&mut buf)
            .expect("encoding to vec should never fail");
        buf
    }

    /// Decode an edit message from protobuf bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EditMessageParseError> {
        let proto_message = protobuf::csp_e2e::EditMessage::decode(bytes)
            .map_err(|error| EditMessageParseError::Protobuf(error.to_string()))?;
        Ok(Self {
            message_id: MessageId::from_u64(proto_message.message_id),
            text: proto_message.text,
        })
    }
}

/// A delete message.
///
/// Contains the message ID of the message to be deleted.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DeleteMessage {
    /// The message ID of the message to be deleted
    pub message_id: MessageId,
}

impl DeleteMessage {
    /// Create a new [`DeleteMessage`].
    #[must_use]
    pub const fn new(message_id: MessageId) -> Self {
        Self { message_id }
    }

    /// Encode this message to its wire-format bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let proto_message = protobuf::csp_e2e::DeleteMessage {
            message_id: self.message_id.as_u64(),
        };
        let mut buf = Vec::with_capacity(proto_message.encoded_len());
        proto_message
            .encode(&mut buf)
            .expect("encoding to vec should never fail");
        buf
    }

    /// Decode a delete message from protobuf bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeleteMessageParseError> {
        let proto_message = protobuf::csp_e2e::DeleteMessage::decode(bytes)
            .map_err(|error| DeleteMessageParseError::Protobuf(error.to_string()))?;
        Ok(Self {
            message_id: MessageId::from_u64(proto_message.message_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod edit_message {
        use super::*;

        #[test]
        fn new() {
            let msg_id = MessageId::from_u64(0x0123_4567_89ab_cdef);
            let msg = EditMessage::new(msg_id, "edited text".into());
            assert_eq!(msg.message_id, msg_id);
            assert_eq!(msg.text, "edited text");
        }

        #[test]
        fn encode() {
            let msg_id = MessageId::from_u64(0x0123_4567_89ab_cdef);
            let msg = EditMessage::new(msg_id, "new text".into());
            let bytes = msg.encode();
            // Verify it's valid protobuf encoding
            let proto_message = protobuf::csp_e2e::EditMessage::decode(&*bytes).unwrap();
            assert_eq!(proto_message.message_id, 0x0123_4567_89ab_cdef);
            assert_eq!(proto_message.text, "new text");
        }

        #[test]
        fn decode() {
            let message_id = MessageId::from_u64(0xfedc_ba98_7654_3210);
            let proto_message = protobuf::csp_e2e::EditMessage {
                message_id: message_id.as_u64(),
                text: "replacement".into(),
            };
            let mut proto_bytes = Vec::new();
            proto_message.encode(&mut proto_bytes).unwrap();

            let msg = EditMessage::decode(&proto_bytes).unwrap();
            assert_eq!(msg.message_id, message_id);
            assert_eq!(msg.text, "replacement");
        }

        #[test]
        fn decode_invalid_protobuf() {
            let invalid_bytes = [0xff, 0xff, 0xff]; // Invalid protobuf data
            let err = EditMessage::decode(&invalid_bytes).unwrap_err();
            assert!(matches!(err, EditMessageParseError::Protobuf(_)));
        }

        #[test]
        fn round_trip() {
            let original =
                EditMessage::new(MessageId::from_u64(0x1234_5678_9abc_def0), "hello".into());
            let decoded = EditMessage::decode(&original.encode()).unwrap();
            assert_eq!(decoded, original);
        }
    }

    mod delete_message {
        use super::*;

        #[test]
        fn new() {
            let msg_id = MessageId::from_u64(0x0123_4567_89ab_cdef);
            let msg = DeleteMessage::new(msg_id);
            assert_eq!(msg.message_id, msg_id);
        }

        #[test]
        fn encode() {
            let msg_id = MessageId::from_u64(0x0123_4567_89ab_cdef);
            let msg = DeleteMessage::new(msg_id);
            let bytes = msg.encode();
            // Verify it's valid protobuf encoding
            let proto_message = protobuf::csp_e2e::DeleteMessage::decode(&*bytes).unwrap();
            assert_eq!(proto_message.message_id, 0x0123_4567_89ab_cdef);
        }

        #[test]
        fn decode() {
            let message_id = MessageId::from_u64(0xfedc_ba98_7654_3210);
            let proto_message = protobuf::csp_e2e::DeleteMessage {
                message_id: message_id.as_u64(),
            };
            let mut proto_bytes = Vec::new();
            proto_message.encode(&mut proto_bytes).unwrap();

            let msg = DeleteMessage::decode(&proto_bytes).unwrap();
            assert_eq!(msg.message_id, message_id);
        }

        #[test]
        fn decode_invalid_protobuf() {
            let invalid_bytes = [0xff, 0xff, 0xff]; // Invalid protobuf data
            let err = DeleteMessage::decode(&invalid_bytes).unwrap_err();
            assert!(matches!(err, DeleteMessageParseError::Protobuf(_)));
        }

        #[test]
        fn round_trip() {
            let original = DeleteMessage::new(MessageId::from_u64(0x1234_5678_9abc_def0));
            let decoded = DeleteMessage::decode(&original.encode()).unwrap();
            assert_eq!(decoded, original);
        }
    }
}
