//! Delivery receipt message related types.

use thiserror::Error;

/// A delivery receipt is sent by the recipient of a message when certain events happen.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeliveryReceipt {
    /// Message is received
    Received,
    /// Message is read
    Read,
    /// Message is acknowledged (thumbs-up reaction)
    Acknowledged,
    /// Message is declined (thumbs-down reaction)
    Declined,
    /// Another receipt type (unknown)
    Other(u8),
}

impl From<DeliveryReceipt> for u8 {
    fn from(val: DeliveryReceipt) -> Self {
        match val {
            DeliveryReceipt::Received => 0x01,
            DeliveryReceipt::Read => 0x02,
            DeliveryReceipt::Acknowledged => 0x03,
            DeliveryReceipt::Declined => 0x04,
            DeliveryReceipt::Other(value) => value,
        }
    }
}

impl From<u8> for DeliveryReceipt {
    fn from(value: u8) -> Self {
        match value {
            0x01 => DeliveryReceipt::Received,
            0x02 => DeliveryReceipt::Read,
            0x03 => DeliveryReceipt::Acknowledged,
            0x04 => DeliveryReceipt::Declined,
            other => DeliveryReceipt::Other(other),
        }
    }
}

/// Errors when parsing a delivery receipt message.
#[derive(Debug, PartialEq, Clone, Error)]
pub enum DeliveryReceiptMessageParseError {
    /// Invalid message length (must be a multiple of 8 plus 1)
    #[error("invalid message byte length (must be a multiple of 8 plus 1): {0}")]
    InvalidLength(usize),

    /// Message IDs section is empty (at least one message ID is required)
    #[error("missing message IDs (at least one is required)")]
    MissingMessageIds,
}

/// A delivery receipt message.
///
/// Contains a [`DeliveryReceipt`] status and one or more message IDs (as
/// `u64`) whose status should be updated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceiptMessage {
    /// The delivery receipt status
    pub receipt: DeliveryReceipt,
    /// One or more message IDs whose status should be updated
    pub message_ids: Vec<u64>,
}

impl DeliveryReceiptMessage {
    /// Create a new [`DeliveryReceiptMessage`].
    #[must_use]
    pub fn new(receipt: DeliveryReceipt, message_id: u64, additional_message_ids: &[u64]) -> Self {
        let mut message_ids = Vec::with_capacity(additional_message_ids.len().saturating_add(1));
        message_ids.push(message_id);
        message_ids.extend_from_slice(additional_message_ids);
        Self {
            receipt,
            message_ids,
        }
    }

    /// Encode this message to its wire-format bytes.
    ///
    /// The first byte is the status, followed by one or more 8-byte
    /// little-endian message IDs.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let ids_len = self.message_ids.len().saturating_mul(8);
        let mut buf = Vec::with_capacity(ids_len.saturating_add(1));
        buf.push(u8::from(self.receipt));
        for &id in &self.message_ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        buf
    }

    /// Decode a delivery receipt message from raw bytes.
    ///
    /// The first byte is interpreted as the status, the remaining bytes as one
    /// or more little-endian `u64` message IDs. The total length must be a
    /// multiple of 8 plus 1 (i.e. 1 status byte + N × 8 message-ID bytes).
    pub fn decode(bytes: &[u8]) -> Result<Self, DeliveryReceiptMessageParseError> {
        // Validate overall length: must be 8n + 1 for some n >= 0
        let len = bytes.len();
        if len
            .checked_sub(1)
            .is_none_or(|rest| rest.checked_rem(8) != Some(0))
        {
            return Err(DeliveryReceiptMessageParseError::InvalidLength(len));
        }

        // Length is at least 1, so split_first succeeds
        let (&status_byte, rest) = bytes
            .split_first()
            .expect("missing first byte post-validation");

        // Parse status
        let receipt = DeliveryReceipt::from(status_byte);

        // Parse message IDs
        if rest.is_empty() {
            return Err(DeliveryReceiptMessageParseError::MissingMessageIds);
        }
        let message_ids = rest
            .chunks_exact(8)
            .map(|chunk| {
                u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8) guarantees failed"))
            })
            .collect();

        Ok(Self {
            receipt,
            message_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod delivery_receipt {
        use super::*;

        #[test]
        fn to_u8() {
            assert_eq!(u8::from(DeliveryReceipt::Received), 0x01);
            assert_eq!(u8::from(DeliveryReceipt::Read), 0x02);
            assert_eq!(u8::from(DeliveryReceipt::Acknowledged), 0x03);
            assert_eq!(u8::from(DeliveryReceipt::Declined), 0x04);
            assert_eq!(u8::from(DeliveryReceipt::Other(0x42)), 0x42);
        }

        #[test]
        fn from_u8() {
            assert_eq!(DeliveryReceipt::from(0x01), DeliveryReceipt::Received);
            assert_eq!(DeliveryReceipt::from(0x02), DeliveryReceipt::Read);
            assert_eq!(DeliveryReceipt::from(0x03), DeliveryReceipt::Acknowledged);
            assert_eq!(DeliveryReceipt::from(0x04), DeliveryReceipt::Declined);
            assert_eq!(DeliveryReceipt::from(0x00), DeliveryReceipt::Other(0x00));
            assert_eq!(DeliveryReceipt::from(0x05), DeliveryReceipt::Other(0x05));
            assert_eq!(DeliveryReceipt::from(0xff), DeliveryReceipt::Other(0xff));
        }

        #[test]
        fn round_trip() {
            let known = DeliveryReceipt::Received;
            assert_eq!(DeliveryReceipt::from(u8::from(known)), known);

            let other = DeliveryReceipt::Other(0x42);
            assert_eq!(DeliveryReceipt::from(u8::from(other)), other);
        }
    }

    mod delivery_receipt_message {
        use super::*;

        #[test]
        fn new_single_id() {
            let msg = DeliveryReceiptMessage::new(DeliveryReceipt::Received, 42, &[]);
            assert_eq!(msg.receipt, DeliveryReceipt::Received);
            assert_eq!(msg.message_ids, vec![42]);
        }

        #[test]
        fn new_multiple_ids() {
            let msg = DeliveryReceiptMessage::new(DeliveryReceipt::Read, 1, &[2, 3]);
            assert_eq!(msg.receipt, DeliveryReceipt::Read);
            assert_eq!(msg.message_ids, vec![1, 2, 3]);
        }

        #[test]
        fn encode_single_id() {
            let msg =
                DeliveryReceiptMessage::new(DeliveryReceipt::Received, 0x0102_0304_0506_0708, &[]);
            let bytes = msg.encode();
            assert_eq!(bytes[0], 0x01); // status
            assert_eq!(&bytes[1..], 0x0102_0304_0506_0708_u64.to_le_bytes());
        }

        #[test]
        fn encode_multiple_ids() {
            let msg = DeliveryReceiptMessage::new(DeliveryReceipt::Declined, 1, &[2]);
            let bytes = msg.encode();
            assert_eq!(bytes.len(), 1 + 2 * 8);
            assert_eq!(bytes[0], 0x04);
            assert_eq!(&bytes[1..9], 1_u64.to_le_bytes());
            assert_eq!(&bytes[9..17], 2_u64.to_le_bytes());
        }

        #[test]
        fn decode_single_id() {
            let mut bytes = vec![0x02]; // Read
            bytes.extend_from_slice(&42_u64.to_le_bytes());
            let msg = DeliveryReceiptMessage::decode(&bytes).unwrap();
            assert_eq!(msg.receipt, DeliveryReceipt::Read);
            assert_eq!(msg.message_ids, vec![42]);
        }

        #[test]
        fn decode_multiple_ids() {
            let mut bytes = vec![0x03]; // Acknowledged
            bytes.extend_from_slice(&100_u64.to_le_bytes());
            bytes.extend_from_slice(&200_u64.to_le_bytes());
            bytes.extend_from_slice(&300_u64.to_le_bytes());
            let msg = DeliveryReceiptMessage::decode(&bytes).unwrap();
            assert_eq!(msg.receipt, DeliveryReceipt::Acknowledged);
            assert_eq!(msg.message_ids, vec![100, 200, 300]);
        }

        #[test]
        fn decode_empty() {
            let err = DeliveryReceiptMessage::decode(&[]).unwrap_err();
            assert_eq!(err, DeliveryReceiptMessageParseError::InvalidLength(0));
        }

        #[test]
        fn decode_unknown_status() {
            let mut bytes = vec![0xff];
            bytes.extend_from_slice(&1_u64.to_le_bytes());
            let msg = DeliveryReceiptMessage::decode(&bytes).unwrap();
            assert_eq!(msg.receipt, DeliveryReceipt::Other(0xff));
            assert_eq!(msg.message_ids, vec![1]);
        }

        #[test]
        fn decode_missing_message_ids() {
            let err = DeliveryReceiptMessage::decode(&[0x01]).unwrap_err();
            assert_eq!(err, DeliveryReceiptMessageParseError::MissingMessageIds);
        }

        #[test]
        fn decode_invalid_length() {
            let bytes = vec![0x01, 1, 2, 3]; // length 4 is not 8n + 1
            let err = DeliveryReceiptMessage::decode(&bytes).unwrap_err();
            assert_eq!(err, DeliveryReceiptMessageParseError::InvalidLength(4));
        }

        #[test]
        fn round_trip_single_id() {
            let original = DeliveryReceiptMessage::new(DeliveryReceipt::Received, 12345, &[]);
            let decoded = DeliveryReceiptMessage::decode(&original.encode()).unwrap();
            assert_eq!(decoded, original);
        }

        #[test]
        fn round_trip_multiple_ids() {
            let original = DeliveryReceiptMessage::new(
                DeliveryReceipt::Read,
                0,
                &[u64::MAX, 0x0102_0304_0506_0708],
            );
            let decoded = DeliveryReceiptMessage::decode(&original.encode()).unwrap();
            assert_eq!(decoded, original);
        }
    }
}
