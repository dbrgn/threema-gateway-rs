//! Types used in the Threema end-to-end protocol.

use std::str::Utf8Error;

use thiserror::Error;

pub(crate) mod file;

/// A message type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    /// Text message
    Text,
    /// Image message (deprecated)
    Image,
    /// Video message (deprecated)
    Video,
    /// File message
    File,
    /// Another message type
    Other(u8),
}

impl From<MessageType> for u8 {
    fn from(val: MessageType) -> Self {
        match val {
            MessageType::Text => 0x01,
            MessageType::Image => 0x02,
            MessageType::Video => 0x13,
            MessageType::File => 0x17,
            MessageType::Other(msgtype_byte) => msgtype_byte,
        }
    }
}

/// Errors while decoding a message.
#[derive(Debug, Error)]
pub enum MessageDecodeError {
    /// Invalid UTF-8
    #[error("invalid utf-8: {0}")]
    InvalidUtf8(Utf8Error),

    /// JSON error
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// An encoded [`E2eMessage`] along with the message type.
pub struct EncodedE2eMessage {
    /// The message type
    pub message_type: MessageType,
    /// The encoded unpadded message bytes
    pub message_bytes: Vec<u8>,
}

/// A message on the end-to-end layer, exchanged in encrypted form between Threema IDs.
#[derive(Clone)]
pub enum E2eMessage {
    /// Text message
    Text(String),
    /// File message
    File(file::FileMessage),
    /// Another message
    Other {
        /// The message type
        message_type: MessageType,
        /// The raw message bytes (without padding)
        message_bytes: Vec<u8>,
    },
}

impl E2eMessage {
    /// Encode this message, return an [`EncodedE2eMessage`]
    #[must_use]
    pub fn encode(&self) -> EncodedE2eMessage {
        match self {
            Self::Text(text) => EncodedE2eMessage {
                message_type: MessageType::Text,
                message_bytes: text.as_bytes().to_vec(),
            },
            Self::File(file_message) => EncodedE2eMessage {
                message_type: MessageType::File,
                message_bytes: serde_json::to_vec(file_message)
                    .expect("Failed to serialize file message to JSON"),
            },
            Self::Other {
                message_type,
                message_bytes,
            } => EncodedE2eMessage {
                message_type: *message_type,
                message_bytes: message_bytes.clone(),
            },
        }
    }

    /// Decode this message from unpadded data.
    pub fn decode(
        message_type: MessageType,
        message_bytes: &[u8],
    ) -> Result<Self, MessageDecodeError> {
        match message_type {
            MessageType::Text => {
                let text = str::from_utf8(message_bytes)
                    .map_err(MessageDecodeError::InvalidUtf8)?
                    .to_owned();
                Ok(Self::Text(text))
            }
            MessageType::File => {
                let json_text =
                    str::from_utf8(message_bytes).map_err(MessageDecodeError::InvalidUtf8)?;
                let file_message = serde_json::from_str::<file::FileMessage>(json_text)?;
                Ok(Self::File(file_message))
            }
            other => Ok(Self::Other {
                message_type: other,
                message_bytes: message_bytes.to_vec(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use crate::{Key, protocol::BlobId};

    use super::*;

    /// Helper to build a minimal [`file::FileMessage`] for testing.
    fn sample_file_message() -> file::FileMessage {
        let key = Key::from([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ]);
        let blob_id = BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap();
        file::FileMessage::builder(blob_id, key, "application/pdf", 1024)
            .file_name("test.pdf")
            .build()
            .unwrap()
    }

    mod encode {
        use super::*;

        #[test]
        fn text_message() {
            let encoded = E2eMessage::Text("Hello".into()).encode();
            assert_eq!(encoded.message_type, MessageType::Text);
            assert_eq!(encoded.message_bytes, b"Hello");
        }

        #[test]
        fn text_message_unicode() {
            let text = "Hallo Welt! \u{1F600}";
            let encoded = E2eMessage::Text(text.into()).encode();
            assert_eq!(encoded.message_type, MessageType::Text);
            assert_eq!(encoded.message_bytes, text.as_bytes());
        }

        #[test]
        fn file_message() {
            let file_msg = sample_file_message();
            let encoded = E2eMessage::File(file_msg).encode();
            assert_eq!(encoded.message_type, MessageType::File);

            let json_value: serde_json::Value =
                serde_json::from_slice(&encoded.message_bytes).expect("valid JSON");
            insta::assert_json_snapshot!(json_value);
        }

        #[test]
        fn other_message() {
            let encoded = E2eMessage::Other {
                message_type: MessageType::Other(0x42),
                message_bytes: vec![1, 2, 3],
            }
            .encode();
            assert_eq!(encoded.message_type, MessageType::Other(0x42));
            assert_eq!(encoded.message_bytes, vec![1, 2, 3]);
        }

        #[test]
        fn other_with_known_type() {
            // This is not how the type should be used, but it's not invalid
            let encoded = E2eMessage::Other {
                message_type: MessageType::Image,
                message_bytes: vec![0xff, 0xd8],
            }
            .encode();
            assert_eq!(encoded.message_type, MessageType::Image);
            assert_eq!(encoded.message_bytes, vec![0xff, 0xd8]);
        }
    }

    mod decode {
        use super::*;

        #[test]
        fn text_message() {
            let msg = E2eMessage::decode(MessageType::Text, b"Hello").unwrap();
            let E2eMessage::Text(text) = msg else {
                panic!("expected Text variant");
            };
            assert_eq!(text, "Hello");
        }

        #[test]
        fn text_message_unicode() {
            let text = "Hallo Welt! \u{1F600}";
            let msg = E2eMessage::decode(MessageType::Text, text.as_bytes()).unwrap();
            let E2eMessage::Text(decoded) = msg else {
                panic!("expected Text variant");
            };
            assert_eq!(decoded, text);
        }

        #[test]
        fn text_message_invalid_utf8() {
            let invalid = [0xff, 0xfe];
            let Err(err) = E2eMessage::decode(MessageType::Text, &invalid) else {
                panic!("expected Err");
            };
            assert!(
                matches!(err, MessageDecodeError::InvalidUtf8(_)),
                "expected InvalidUtf8, got {err:?}"
            );
        }

        #[test]
        fn file_message() {
            let file_msg = sample_file_message();
            let json_bytes = serde_json::to_vec(&file_msg).unwrap();

            let msg = E2eMessage::decode(MessageType::File, &json_bytes).unwrap();
            let E2eMessage::File(decoded) = msg else {
                panic!("expected File variant");
            };
            assert_eq!(decoded, file_msg);
        }

        #[test]
        fn file_message_invalid_utf8() {
            let invalid = [0xff, 0xfe];
            let Err(err) = E2eMessage::decode(MessageType::File, &invalid) else {
                panic!("expected Err");
            };
            assert!(
                matches!(err, MessageDecodeError::InvalidUtf8(_)),
                "expected InvalidUtf8, got {err:?}"
            );
        }

        #[test]
        fn file_message_invalid_json() {
            let bad_json = b"{ not valid json }";
            let Err(err) = E2eMessage::decode(MessageType::File, bad_json) else {
                panic!("expected Err");
            };
            assert!(
                matches!(err, MessageDecodeError::Json(_)),
                "expected Json, got {err:?}"
            );
        }

        #[test]
        fn other_message() {
            let bytes = vec![10, 20, 30];
            let msg = E2eMessage::decode(MessageType::Other(0x42), &bytes).unwrap();
            let E2eMessage::Other {
                message_type,
                message_bytes,
            } = msg
            else {
                panic!("expected Other variant");
            };
            assert_eq!(message_type, MessageType::Other(0x42));
            assert_eq!(message_bytes, bytes);
        }
    }
}
