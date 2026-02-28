//! Types used in the Threema end-to-end protocol.

use crate::errors::MessageDecodeError;

pub mod delivery_receipt;
pub mod file;
pub mod location;
pub mod typing_indicator;

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
    /// Location message
    Location,
    /// Delivery receipt (received / read)
    DeliveryReceipt,
    /// Typing indicator
    TypingIndicator,
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
            MessageType::Location => 0x10,
            MessageType::DeliveryReceipt => 0x80,
            MessageType::TypingIndicator => 0x90,
            MessageType::Other(msgtype_byte) => msgtype_byte,
        }
    }
}

impl From<u8> for MessageType {
    fn from(val: u8) -> Self {
        match val {
            0x01 => MessageType::Text,
            0x02 => MessageType::Image,
            0x10 => MessageType::Location,
            0x13 => MessageType::Video,
            0x17 => MessageType::File,
            0x80 => MessageType::DeliveryReceipt,
            0x90 => MessageType::TypingIndicator,
            other => MessageType::Other(other),
        }
    }
}

/// An encoded [`E2eMessage`] along with the message type.
pub struct EncodedE2eMessage {
    /// The message type
    pub message_type: MessageType,
    /// The encoded unpadded message bytes
    pub message_bytes: Vec<u8>,
}

/// A message on the end-to-end layer, exchanged in encrypted form between Threema IDs.
#[derive(Debug, Clone, PartialEq)]
pub enum E2eMessage {
    /// Text message
    Text(String),
    /// File message
    File(file::FileMessage),
    /// Location message
    Location(location::LocationMessage),
    /// Delivery receipt message
    DeliveryReceipt(delivery_receipt::DeliveryReceiptMessage),
    /// Typing indicator message
    TypingIndicator(typing_indicator::TypingIndicatorMessage),
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
            Self::Location(location_message) => EncodedE2eMessage {
                message_type: MessageType::Location,
                message_bytes: location_message.encode(),
            },
            Self::DeliveryReceipt(delivery_receipt_message) => EncodedE2eMessage {
                message_type: MessageType::DeliveryReceipt,
                message_bytes: delivery_receipt_message.encode(),
            },
            Self::TypingIndicator(typing_indicator_message) => EncodedE2eMessage {
                message_type: MessageType::TypingIndicator,
                message_bytes: typing_indicator_message.encode(),
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
            MessageType::Location => {
                let text =
                    str::from_utf8(message_bytes).map_err(MessageDecodeError::InvalidUtf8)?;
                let location_message = text.parse::<location::LocationMessage>()?;
                Ok(Self::Location(location_message))
            }
            MessageType::DeliveryReceipt => {
                let delivery_receipt_message =
                    delivery_receipt::DeliveryReceiptMessage::decode(message_bytes)?;
                Ok(Self::DeliveryReceipt(delivery_receipt_message))
            }
            MessageType::TypingIndicator => {
                let typing_indicator_message =
                    typing_indicator::TypingIndicatorMessage::decode(message_bytes)?;
                Ok(Self::TypingIndicator(typing_indicator_message))
            }
            other => Ok(Self::Other {
                message_type: other,
                message_bytes: message_bytes.to_vec(),
            }),
        }
    }

    /// Decode from raw decrypted message bytes.
    ///
    /// The first byte is interpreted as the message type byte, the remaining
    /// bytes are the message payload. This matches the format returned by
    /// [`IncomingMessage::decrypt_box`](crate::IncomingMessage::decrypt_box)
    /// and [`E2eApi::decrypt_incoming_message`](crate::E2eApi::decrypt_incoming_message).
    pub fn decode_from_decrypted_bytes(bytes: &[u8]) -> Result<Self, MessageDecodeError> {
        let (&type_byte, payload) = bytes
            .split_first()
            .ok_or(MessageDecodeError::EmptyMessage)?;
        Self::decode(MessageType::from(type_byte), payload)
    }

    /// Return the associated message type.
    #[must_use]
    pub fn message_type(&self) -> MessageType {
        match self {
            E2eMessage::Text(_) => MessageType::Text,
            E2eMessage::File(_) => MessageType::File,
            E2eMessage::Location(_) => MessageType::Location,
            E2eMessage::DeliveryReceipt(_) => MessageType::DeliveryReceipt,
            E2eMessage::TypingIndicator(_) => MessageType::TypingIndicator,
            E2eMessage::Other { message_type, .. } => *message_type,
        }
    }
}

impl From<String> for E2eMessage {
    fn from(value: String) -> Self {
        E2eMessage::Text(value)
    }
}

impl From<file::FileMessage> for E2eMessage {
    fn from(value: file::FileMessage) -> Self {
        E2eMessage::File(value)
    }
}

impl From<location::LocationMessage> for E2eMessage {
    fn from(value: location::LocationMessage) -> Self {
        E2eMessage::Location(value)
    }
}

impl From<delivery_receipt::DeliveryReceiptMessage> for E2eMessage {
    fn from(value: delivery_receipt::DeliveryReceiptMessage) -> Self {
        E2eMessage::DeliveryReceipt(value)
    }
}

impl From<typing_indicator::TypingIndicatorMessage> for E2eMessage {
    fn from(value: typing_indicator::TypingIndicatorMessage) -> Self {
        E2eMessage::TypingIndicator(value)
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

    mod message_type {
        use rstest::rstest;

        use super::*;

        #[rstest]
        #[case::zero(0x00, MessageType::Other(0x00))]
        #[case::text(0x01, MessageType::Text)]
        #[case::image(0x02, MessageType::Image)]
        #[case::location(0x10, MessageType::Location)]
        #[case::video(0x13, MessageType::Video)]
        #[case::file(0x17, MessageType::File)]
        #[case::other(0x42, MessageType::Other(0x42))]
        fn from_u8(#[case] byte: u8, #[case] expected: MessageType) {
            assert_eq!(MessageType::from(byte), expected);
        }

        #[rstest]
        #[case::text(MessageType::Text, 0x01)]
        #[case::image(MessageType::Image, 0x02)]
        #[case::video(MessageType::Video, 0x13)]
        #[case::file(MessageType::File, 0x17)]
        #[case::location(MessageType::Location, 0x10)]
        #[case::other(MessageType::Other(0x42), 0x42)]
        fn to_u8(#[case] msgtype: MessageType, #[case] expected: u8) {
            let byte: u8 = msgtype.into();
            assert_eq!(byte, expected);
        }

        #[test]
        fn round_trip() {
            let original = MessageType::File;
            let byte: u8 = original.into();
            let restored = MessageType::from(byte);
            assert_eq!(restored, original);
        }
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
        fn location_message() {
            let loc_msg = location::LocationMessage::builder(47.3769, 8.5417)
                .address("Bahnhofplatz, 8001 Zürich")
                .build()
                .unwrap();
            let encoded = E2eMessage::Location(loc_msg).encode();
            assert_eq!(encoded.message_type, MessageType::Location);
            assert_eq!(
                String::from_utf8(encoded.message_bytes).expect("valid utf8"),
                "47.3769,8.5417\nBahnhofplatz, 8001 Zürich"
            );
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

    #[expect(
        clippy::float_cmp,
        clippy::default_numeric_fallback,
        reason = "Allowed in tests"
    )]
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
        fn location_message() {
            let payload = "47.3769,8.5417\nZürich HB\nBahnhofplatz, 8001 Zürich".as_bytes();
            let msg = E2eMessage::decode(MessageType::Location, payload).unwrap();
            let E2eMessage::Location(decoded) = msg else {
                panic!("expected Location variant");
            };
            assert_eq!(decoded.coordinates.latitude(), 47.3769);
            assert_eq!(decoded.coordinates.longitude(), 8.5417_f64);
            assert_eq!(decoded.accuracy, None);
            let addr = decoded.address.as_ref().expect("address should be set");
            assert_eq!(addr.name.as_deref(), Some("Zürich HB"));
            assert_eq!(addr.address, "Bahnhofplatz, 8001 Zürich");
        }

        #[test]
        fn location_message_invalid_utf8() {
            let invalid = [0xff, 0xfe];
            let Err(err) = E2eMessage::decode(MessageType::Location, &invalid) else {
                panic!("expected Err");
            };
            assert!(
                matches!(err, MessageDecodeError::InvalidUtf8(_)),
                "expected InvalidUtf8, got {err:?}"
            );
        }

        #[test]
        fn location_message_invalid_content() {
            let bad = b"not-a-float,8.5417";
            let Err(err) = E2eMessage::decode(MessageType::Location, bad) else {
                panic!("expected Err");
            };
            assert!(
                matches!(err, MessageDecodeError::InvalidLocation(_)),
                "expected Location, got {err:?}"
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

    mod decode_from_decrypted_bytes {
        use super::*;

        #[test]
        fn text_message() {
            let bytes = [0x01, b'H', b'i'];
            let msg = E2eMessage::decode_from_decrypted_bytes(&bytes).unwrap();
            let E2eMessage::Text(text) = msg else {
                panic!("expected Text variant");
            };
            assert_eq!(text, "Hi");
        }

        #[test]
        fn file_message() {
            let file_msg = sample_file_message();
            let json_bytes = serde_json::to_vec(&file_msg).unwrap();
            let mut bytes = vec![0x17];
            bytes.extend_from_slice(&json_bytes);

            let msg = E2eMessage::decode_from_decrypted_bytes(&bytes).unwrap();
            let E2eMessage::File(decoded) = msg else {
                panic!("expected File variant");
            };
            assert_eq!(decoded, file_msg);
        }

        #[test]
        fn other_message() {
            let bytes = [0x42, 1, 2, 3];
            let msg = E2eMessage::decode_from_decrypted_bytes(&bytes).unwrap();
            let E2eMessage::Other {
                message_type,
                message_bytes,
            } = msg
            else {
                panic!("expected Other variant");
            };
            assert_eq!(message_type, MessageType::Other(0x42));
            assert_eq!(message_bytes, vec![1, 2, 3]);
        }

        #[test]
        fn empty_bytes() {
            let bytes = [];
            let Err(err) = E2eMessage::decode_from_decrypted_bytes(&bytes) else {
                panic!("expected Err");
            };
            assert!(
                matches!(err, MessageDecodeError::EmptyMessage),
                "expected EmptyMessage, got {err:?}"
            );
        }

        #[test]
        fn type_byte_only() {
            let bytes = [0x01];
            let msg = E2eMessage::decode_from_decrypted_bytes(&bytes).unwrap();
            let E2eMessage::Text(text) = msg else {
                panic!("expected Text variant");
            };
            assert_eq!(text, "");
        }
    }

    mod e2e_message_type {
        use crate::{E2eMessage, protocol::e2e::MessageType};

        #[test]
        fn message_type_text() {
            let message_type = E2eMessage::Text("hello".into()).message_type();
            assert_eq!(message_type, MessageType::Text);
        }

        #[test]
        fn message_type_other() {
            let message_type = E2eMessage::Other {
                message_type: MessageType::Video,
                message_bytes: vec![],
            }
            .message_type();
            assert_eq!(message_type, MessageType::Video);
        }
    }
}
