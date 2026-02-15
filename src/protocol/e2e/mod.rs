//! Types used in the end-to-end protocol.

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
    /// Delivery receipt
    DeliveryReceipt,
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
            MessageType::DeliveryReceipt => 0x80,
            MessageType::Other(msgtype_byte) => msgtype_byte,
        }
    }
}
