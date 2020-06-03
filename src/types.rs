use std::default::Default;
use std::fmt;
use std::str::FromStr;
use std::string::ToString;

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use serde::{Serialize, Serializer};

use crate::errors::ApiError;
use crate::{Key, Mime};

/// A message type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageType {
    Text,
    Image,
    Video,
    File,
    DeliveryReceipt,
}

impl Into<u8> for MessageType {
    fn into(self) -> u8 {
        match self {
            MessageType::Text => 0x01,
            MessageType::Image => 0x02,
            MessageType::Video => 0x13,
            MessageType::File => 0x17,
            MessageType::DeliveryReceipt => 0x80,
        }
    }
}

/// The rendering type influences how a file message is displayed on the device
/// of the recipient.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RenderingType {
    /// Display as default file message
    File,
    /// Display as media file message (e.g. image or audio message)
    Media,
    /// Display as sticker (images with transparency, rendered without bubble)
    Sticker,
}

impl Into<u8> for RenderingType {
    fn into(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Media => 1,
            Self::Sticker => 2,
        }
    }
}

impl Serialize for RenderingType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.clone().into())
    }
}

impl Default for RenderingType {
    fn default() -> Self {
        RenderingType::File
    }
}

/// A file message.
#[derive(Debug, Serialize)]
pub struct FileMessage {
    #[serde(rename = "b")]
    pub file_blob_id: BlobId,
    #[serde(rename = "t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_blob_id: Option<BlobId>,
    #[serde(rename = "k")]
    #[serde(serialize_with = "key_to_hex")]
    pub blob_encryption_key: Key,
    #[serde(rename = "m")]
    #[serde(serialize_with = "serialize_to_string")]
    pub mime_type: Mime,
    #[serde(rename = "n")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(rename = "s")]
    pub file_size_bytes: u32,
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "j")]
    pub rendering_type: RenderingType,
    #[serde(rename = "i")]
    pub reserved: u8,
}

impl FileMessage {
    /// Create a new file message.
    pub fn new(
        file_blob_id: BlobId,
        thumbnail_blob_id: Option<BlobId>,
        blob_encryption_key: Key,
        mime_type: Mime,
        file_name: Option<String>,
        file_size_bytes: u32,
        description: Option<String>,
        rendering_type: RenderingType,
    ) -> Self {
        FileMessage {
            file_blob_id,
            thumbnail_blob_id,
            blob_encryption_key,
            mime_type,
            file_name,
            file_size_bytes,
            description,
            rendering_type,
            reserved: match rendering_type {
                RenderingType::File => 0,
                RenderingType::Media => 1,
                RenderingType::Sticker => 1,
            },
        }
    }
}

/// A 16-byte blob ID.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BlobId(pub [u8; 16]);

impl BlobId {
    /// Create a new BlobId.
    pub fn new(id: [u8; 16]) -> Self {
        BlobId(id)
    }
}

impl FromStr for BlobId {
    type Err = ApiError;

    /// Create a new BlobId from a 32 character hexadecimal String.
    fn from_str(id: &str) -> Result<Self, Self::Err> {
        let bytes = HEXLOWER_PERMISSIVE
            .decode(id.as_bytes())
            .map_err(|_| ApiError::BadBlobId)?;
        if bytes.len() != 16 {
            return Err(ApiError::BadBlobId);
        }
        let mut arr = [0; 16];
        arr[..].clone_from_slice(&bytes[..bytes.len()]);
        Ok(BlobId(arr))
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

impl Serialize for BlobId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&HEXLOWER.encode(&self.0))
    }
}

fn serialize_to_string<S, T>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: ToString,
{
    serializer.serialize_str(&val.to_string())
}

fn key_to_hex<S: Serializer>(val: &Key, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&HEXLOWER.encode(&val.0))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use serde_json as json;

    use super::*;

    #[test]
    fn test_blob_id_from_str() {
        assert!(BlobId::from_str("0123456789abcdef0123456789abcdef").is_ok());
        assert!(BlobId::from_str("0123456789abcdef0123456789abcdeF").is_ok());
        assert!(BlobId::from_str("0123456789abcdef0123456789abcde").is_err());
        assert!(BlobId::from_str("0123456789abcdef0123456789abcdef\n").is_err());
        assert!(BlobId::from_str("0123456789abcdef0123456789abcdeg").is_err());

        assert_eq!(
            BlobId::from_str("000102030405060708090a0b0c0d0eff").unwrap(),
            BlobId::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xff])
        );
    }

    #[test]
    fn test_serialize_to_string_minimal() {
        let pk = Key([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ]);
        let msg = FileMessage::new(
            BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap(),
            None,
            pk,
            "application/pdf".parse().unwrap(),
            None,
            2048,
            None,
            RenderingType::File,
        );
        let data = json::to_string(&msg).unwrap();
        let deserialized: HashMap<String, json::Value> = json::from_str(&data).unwrap();

        assert_eq!(deserialized.keys().len(), 6);
        assert_eq!(
            deserialized.get("b").unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(deserialized.get("t"), None);
        assert_eq!(
            deserialized.get("k").unwrap(),
            "0102030401020304010203040102030401020304010203040102030401020304"
        );
        assert_eq!(deserialized.get("m").unwrap(), "application/pdf");
        assert_eq!(deserialized.get("n"), None);
        assert_eq!(deserialized.get("s").unwrap(), 2048);
        assert_eq!(deserialized.get("j").unwrap(), 0);
        assert_eq!(deserialized.get("i").unwrap(), 0);
        assert_eq!(deserialized.get("d"), None);
    }

    #[test]
    fn test_serialize_to_string_full() {
        let pk = Key([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ]);
        let msg = FileMessage::new(
            BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap(),
            Some(BlobId::from_str("abcdef0123456789abcdef0123456789").unwrap()),
            pk,
            "application/pdf".parse().unwrap(),
            Some("secret.pdf".into()),
            2048,
            Some("This is a fancy file".into()),
            RenderingType::Sticker,
        );
        let data = json::to_string(&msg).unwrap();
        let deserialized: HashMap<String, json::Value> = json::from_str(&data).unwrap();

        assert_eq!(deserialized.keys().len(), 9);
        assert_eq!(
            deserialized.get("b").unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            deserialized.get("t").unwrap(),
            "abcdef0123456789abcdef0123456789"
        );
        assert_eq!(
            deserialized.get("k").unwrap(),
            "0102030401020304010203040102030401020304010203040102030401020304"
        );
        assert_eq!(deserialized.get("m").unwrap(), "application/pdf");
        assert_eq!(deserialized.get("n").unwrap(), "secret.pdf");
        assert_eq!(deserialized.get("s").unwrap(), 2048);
        assert_eq!(deserialized.get("j").unwrap(), 2);
        assert_eq!(deserialized.get("i").unwrap(), 1);
        assert_eq!(deserialized.get("d").unwrap(), "This is a fancy file");
    }
}
