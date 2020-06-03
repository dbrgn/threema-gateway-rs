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
    pub(crate) file_blob_id: BlobId,
    #[serde(rename = "t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) thumbnail_blob_id: Option<BlobId>,
    #[serde(rename = "k")]
    #[serde(serialize_with = "key_to_hex")]
    pub(crate) blob_encryption_key: Key,
    #[serde(rename = "m")]
    #[serde(serialize_with = "serialize_to_string")]
    pub(crate) mime_type: Mime,
    #[serde(rename = "n")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) file_name: Option<String>,
    #[serde(rename = "s")]
    pub(crate) file_size_bytes: u32,
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(rename = "j")]
    pub(crate) rendering_type: RenderingType,
    #[serde(rename = "i")]
    pub(crate) reserved: u8,
}

impl FileMessage {
    /// Shortcut for [`FileMessageBuilder::new`](struct.FileMessageBuilder.html#method.new).
    pub fn builder(
        file_blob_id: BlobId,
        blob_encryption_key: Key,
        mime_type: Mime,
        file_size_bytes: u32,
    ) -> FileMessageBuilder {
        FileMessageBuilder::new(
            file_blob_id,
            blob_encryption_key,
            mime_type,
            file_size_bytes,
        )
    }
}

/// Builder for [`FileMessage`](struct.FileMessage.html).
pub struct FileMessageBuilder {
    file_blob_id: BlobId,
    thumbnail_blob_id: Option<BlobId>,
    blob_encryption_key: Key,
    mime_type: Mime,
    file_name: Option<String>,
    file_size_bytes: u32,
    description: Option<String>,
    rendering_type: RenderingType,
    reserved: u8,
}

impl FileMessageBuilder {
    /// Create a new [`FileMessage`] builder.
    ///
    /// Before calling this function, you need to symmetrically encrypt the file
    /// data (libsodium secretbox, random key) and upload the ciphertext to the
    /// blob server. Use the nonce `000...1` to encrypt the file data.
    ///
    /// The `file_blob_id` must point to the blob id of the uploaded file data,
    /// encrypted with `blob_encryption_key`.
    ///
    /// The file size needs to be specified in bytes. Note that the size is
    /// only used for download size displaying purposes and has no security
    /// implications.
    ///
    /// [`FileMessage`]: struct.FileMessage.html
    pub fn new(
        file_blob_id: BlobId,
        blob_encryption_key: Key,
        mime_type: Mime,
        file_size_bytes: u32,
    ) -> Self {
        FileMessageBuilder {
            file_blob_id,
            thumbnail_blob_id: None,
            blob_encryption_key,
            mime_type,
            file_name: None,
            file_size_bytes,
            description: None,
            rendering_type: RenderingType::File,
            reserved: 0,
        }
    }

    /// Set a thumbnail.
    ///
    /// Before calling this function, you need to symmetrically encrypt the
    /// thumbnail data (in JPEG format) with the same key used for the file
    /// data and with the nonce `000...2`.
    pub fn thumbnail(self, blob_id: BlobId) -> Self {
        self.thumbnail_opt(Some(blob_id))
    }

    /// Set a thumbnail from an Option.
    ///
    /// Before calling this function, you need to symmetrically encrypt the
    /// thumbnail data (in JPEG format) with the same key used for the file
    /// data and with the nonce `000...2`.
    pub fn thumbnail_opt(mut self, blob_id: Option<BlobId>) -> Self {
        self.thumbnail_blob_id = blob_id;
        self
    }

    /// Set the file name.
    ///
    /// Note that the file name will not be shown in the clients if the
    /// rendering type is not set to `File`.
    pub fn file_name(self, file_name: impl Into<String>) -> Self {
        self.file_name_opt(Some(file_name))
    }

    /// Set the file name from an Option.
    ///
    /// Note that the file name will not be shown in the clients if the
    /// rendering type is not set to `File`.
    pub fn file_name_opt(mut self, file_name: Option<impl Into<String>>) -> Self {
        self.file_name = file_name.map(Into::into);
        self
    }

    /// Set the file description / caption.
    pub fn description(self, description: impl Into<String>) -> Self {
        self.description_opt(Some(description))
    }

    /// Set the file description / caption from an Option.
    pub fn description_opt(mut self, description: Option<impl Into<String>>) -> Self {
        self.description = description.map(Into::into);
        self
    }

    /// Set the rendering type.
    ///
    /// See [`RenderingType`](enum.RenderingType.html) docs for more information.
    pub fn rendering_type(mut self, rendering_type: RenderingType) -> Self {
        self.rendering_type = rendering_type;
        self.reserved = match rendering_type {
            RenderingType::File => 0,
            RenderingType::Media => 1,
            RenderingType::Sticker => 1,
        };
        self
    }

    /// Create a [`FileMessage`] from this builder.
    ///
    /// [`FileMessage`]: struct.FileMessage.html
    pub fn build(self) -> FileMessage {
        FileMessage {
            file_blob_id: self.file_blob_id,
            thumbnail_blob_id: self.thumbnail_blob_id,
            blob_encryption_key: self.blob_encryption_key,
            mime_type: self.mime_type,
            file_name: self.file_name,
            file_size_bytes: self.file_size_bytes,
            description: self.description,
            rendering_type: self.rendering_type,
            reserved: self.reserved,
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
        let msg = FileMessage {
            file_blob_id: BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap(),
            thumbnail_blob_id: None,
            blob_encryption_key: pk,
            mime_type: "application/pdf".parse().unwrap(),
            file_name: None,
            file_size_bytes: 2048,
            description: None,
            rendering_type: RenderingType::File,
            reserved: 0,
        };
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
        let msg = FileMessage {
            file_blob_id: BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap(),
            thumbnail_blob_id: Some(BlobId::from_str("abcdef0123456789abcdef0123456789").unwrap()),
            blob_encryption_key: pk,
            mime_type: "application/pdf".parse().unwrap(),
            file_name: Some("secret.pdf".into()),
            file_size_bytes: 2048,
            description: Some("This is a fancy file".into()),
            rendering_type: RenderingType::Sticker,
            reserved: 1,
        };
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

    #[test]
    fn test_builder() {
        let key = Key([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ]);
        let file_blob_id = BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap();
        let thumb_blob_id = BlobId::from_str("abcdef0123456789abcdef0123456789").unwrap();
        let mime_type: Mime = "image/jpeg".parse().unwrap();
        let msg = FileMessage::builder(file_blob_id.clone(), key.clone(), mime_type.clone(), 2048)
            .thumbnail(thumb_blob_id.clone())
            .file_name("hello.jpg")
            .description(String::from("An image file"))
            .rendering_type(RenderingType::Media)
            .build();

        assert_eq!(msg.file_blob_id, file_blob_id);
        assert_eq!(msg.thumbnail_blob_id, Some(thumb_blob_id));
        assert_eq!(msg.blob_encryption_key, key);
        assert_eq!(msg.mime_type, mime_type);
        assert_eq!(msg.file_name, Some("hello.jpg".to_string()));
        assert_eq!(msg.file_size_bytes, 2048);
        assert_eq!(msg.description, Some("An image file".to_string()));
        assert_eq!(msg.rendering_type, RenderingType::Media);
        assert_eq!(msg.reserved, 1);
    }
}
