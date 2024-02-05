use std::{default::Default, fmt, str::FromStr};

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use serde::{Serialize, Serializer};

use crate::{
    errors::{ApiError, FileMessageBuilderError},
    Key,
};

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

/// The rendering type influences how a file message is displayed on the device
/// of the recipient.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum RenderingType {
    /// Display as default file message
    #[default]
    File,
    /// Display as media file message (e.g. image or audio message)
    Media,
    /// Display as sticker (images with transparency, rendered without bubble)
    Sticker,
}

impl From<RenderingType> for u8 {
    fn from(val: RenderingType) -> Self {
        match val {
            RenderingType::File => 0,
            RenderingType::Media => 1,
            RenderingType::Sticker => 2,
        }
    }
}

impl Serialize for RenderingType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8((*self).into())
    }
}

/// A file message.
#[derive(Debug, Serialize)]
pub struct FileMessage {
    #[serde(rename = "b")]
    file_blob_id: BlobId,
    #[serde(rename = "m")]
    file_media_type: String,

    #[serde(rename = "t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail_blob_id: Option<BlobId>,
    #[serde(rename = "p")]
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail_media_type: Option<String>,

    #[serde(rename = "k")]
    #[serde(serialize_with = "key_to_hex")]
    blob_encryption_key: Key,

    #[serde(rename = "n")]
    #[serde(skip_serializing_if = "Option::is_none")]
    file_name: Option<String>,
    #[serde(rename = "s")]
    file_size_bytes: u32,
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    #[serde(rename = "j")]
    rendering_type: RenderingType,
    #[serde(rename = "i")]
    legacy_rendering_type: u8,

    #[serde(rename = "x")]
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<FileMetadata>,
}

/// Metadata for a file message (depending on media type).
///
/// This data is intended to enhance the layout logic.
#[derive(Debug, Serialize, Default)]
struct FileMetadata {
    #[serde(rename = "a")]
    #[serde(skip_serializing_if = "Option::is_none")]
    animated: Option<bool>,
    #[serde(rename = "h")]
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<u32>,
    #[serde(rename = "w")]
    #[serde(skip_serializing_if = "Option::is_none")]
    width: Option<u32>,
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<f32>,
}

impl FileMetadata {
    /// Return true if all optional fields are set to `None`.
    fn none_set(&self) -> bool {
        self.animated.is_none()
            && self.height.is_none()
            && self.width.is_none()
            && self.duration_seconds.is_none()
    }
}

impl FileMessage {
    /// Shortcut for [`FileMessageBuilder::new`](struct.FileMessageBuilder.html#method.new).
    pub fn builder(
        file_blob_id: BlobId,
        blob_encryption_key: Key,
        media_type: impl Into<String>,
        file_size_bytes: u32,
    ) -> FileMessageBuilder {
        FileMessageBuilder::new(
            file_blob_id,
            blob_encryption_key,
            media_type,
            file_size_bytes,
        )
    }
}

/// Builder for [`FileMessage`](struct.FileMessage.html).
pub struct FileMessageBuilder {
    file_blob_id: BlobId,
    file_media_type: String,
    thumbnail_blob_id: Option<BlobId>,
    thumbnail_media_type: Option<String>,
    blob_encryption_key: Key,
    file_name: Option<String>,
    file_size_bytes: u32,
    description: Option<String>,
    rendering_type: RenderingType,
    metadata: Option<FileMetadata>,
}

impl FileMessageBuilder {
    /// Create a new [`FileMessage`] builder.
    ///
    /// Before calling this function, you need to symmetrically encrypt the
    /// file data with [`encrypt_file_data`](crate::encrypt_file_data) and
    /// upload the ciphertext to the blob server with
    /// [`blob_upload`](crate::E2eApi::blob_upload).
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
        media_type: impl Into<String>,
        file_size_bytes: u32,
    ) -> Self {
        FileMessageBuilder {
            file_blob_id,
            file_media_type: media_type.into(),
            thumbnail_blob_id: None,
            thumbnail_media_type: None,
            blob_encryption_key,
            file_name: None,
            file_size_bytes,
            description: None,
            rendering_type: RenderingType::File,
            metadata: None,
        }
    }

    /// Ensure that an (empty) metadata field is set and return a mutable
    /// reference ot it.
    fn ensure_metadata(&mut self) -> &mut FileMetadata {
        if self.metadata.is_none() {
            self.metadata = Some(FileMetadata::default());
        }
        self.metadata.as_mut().unwrap() // Cannot fail, since we assign metadata above
    }

    /// Set a thumbnail.
    ///
    /// Before calling this function, you need to encrypt and upload the
    /// thumbnail data along with the file data (as described in
    /// [`FileMessageBuilder::new`]).
    pub fn thumbnail(self, blob_id: BlobId, media_type: impl Into<String>) -> Self {
        self.thumbnail_opt(Some((blob_id, media_type)))
    }

    /// Set a thumbnail from an Option.
    ///
    /// Before calling this function, you need to encrypt and upload the
    /// thumbnail data along with the file data (as described in
    /// [`FileMessageBuilder::new`]).
    pub fn thumbnail_opt(mut self, blob: Option<(BlobId, impl Into<String>)>) -> Self {
        match blob {
            Some((blob_id, media_type)) => {
                self.thumbnail_blob_id = Some(blob_id);
                self.thumbnail_media_type = Some(media_type.into());
            }
            None => {
                self.thumbnail_blob_id = None;
                self.thumbnail_media_type = None;
            }
        }
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
        self
    }

    /// Mark this file message as animated.
    ///
    /// May only be used for files with rendering type `Media` or `Sticker`.
    pub fn animated(mut self, animated: bool) -> Self {
        self.ensure_metadata().animated = Some(animated);
        self
    }

    /// Set the dimensions of this file message.
    ///
    /// May only be used for files with rendering type `Media` or `Sticker`.
    pub fn dimensions(mut self, height: u32, width: u32) -> Self {
        let metadata = self.ensure_metadata();
        metadata.height = Some(height);
        metadata.width = Some(width);
        self
    }

    /// Set the duration (in seconds) of this file message.
    ///
    /// May only be used for audio/video files with rendering type `Media`.
    pub fn duration(mut self, seconds: f32) -> Self {
        self.ensure_metadata().duration_seconds = Some(seconds);
        self
    }

    /// Create a [`FileMessage`] from this builder.
    ///
    /// [`FileMessage`]: struct.FileMessage.html
    pub fn build(self) -> Result<FileMessage, FileMessageBuilderError> {
        // Validate some metadata combinations
        if let Some(metadata) = &self.metadata {
            if self.rendering_type == RenderingType::File
                && (metadata.animated.is_some()
                    || metadata.duration_seconds.is_some()
                    || metadata.height.is_some()
                    || metadata.width.is_some())
            {
                return Err(FileMessageBuilderError::IllegalCombination(
                    "File message with rendering type file may not contain media metadata",
                ));
            }
            if self.rendering_type == RenderingType::Sticker && metadata.duration_seconds.is_some()
            {
                return Err(FileMessageBuilderError::IllegalCombination(
                    "File message with rendering type sticker may not contain duration",
                ));
            }
            if self.rendering_type == RenderingType::Media && metadata.none_set() {
                log::warn!("Created FileMessage with rendering type Media but without metadata");
            }
        } else {
            if self.rendering_type == RenderingType::Media {
                log::warn!("Created FileMessage with rendering type Media but without metadata");
            }
        };

        Ok(FileMessage {
            file_blob_id: self.file_blob_id,
            file_media_type: self.file_media_type,
            thumbnail_blob_id: self.thumbnail_blob_id,
            thumbnail_media_type: self.thumbnail_media_type,
            blob_encryption_key: self.blob_encryption_key,
            file_name: self.file_name,
            file_size_bytes: self.file_size_bytes,
            description: self.description,
            rendering_type: self.rendering_type,
            legacy_rendering_type: match self.rendering_type {
                // For compatibility reasons, set `legacy_rendering_type` to 1
                // for media file messages, and 0 otherwise.
                RenderingType::Media => 1,
                _ => 0,
            },
            metadata: self.metadata,
        })
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
            file_media_type: "application/pdf".parse().unwrap(),
            thumbnail_blob_id: None,
            thumbnail_media_type: None,
            blob_encryption_key: pk,
            file_name: None,
            file_size_bytes: 2048,
            description: None,
            rendering_type: RenderingType::File,
            legacy_rendering_type: 0,
            metadata: None,
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
            file_media_type: "application/pdf".parse().unwrap(),
            thumbnail_blob_id: Some(BlobId::from_str("abcdef0123456789abcdef0123456789").unwrap()),
            thumbnail_media_type: Some("image/jpeg".parse().unwrap()),
            blob_encryption_key: pk,
            file_name: Some("secret.pdf".into()),
            file_size_bytes: 2048,
            description: Some("This is a fancy file".into()),
            rendering_type: RenderingType::Sticker,
            legacy_rendering_type: 1,
            metadata: Some(FileMetadata {
                animated: Some(true),
                height: Some(320),
                width: Some(240),
                duration_seconds: Some(12.7),
            }),
        };
        let data = json::to_string(&msg).unwrap();
        let deserialized: HashMap<String, json::Value> = json::from_str(&data).unwrap();

        assert_eq!(deserialized.keys().len(), 11);
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
        assert_eq!(deserialized.get("p").unwrap(), "image/jpeg");
        assert_eq!(deserialized.get("n").unwrap(), "secret.pdf");
        assert_eq!(deserialized.get("s").unwrap(), 2048);
        assert_eq!(deserialized.get("j").unwrap(), 2);
        assert_eq!(deserialized.get("i").unwrap(), 1);
        assert_eq!(deserialized.get("d").unwrap(), "This is a fancy file");
        assert_eq!(deserialized.get("x").unwrap().get("a").unwrap(), true);
        assert_eq!(deserialized.get("x").unwrap().get("h").unwrap(), 320);
        assert_eq!(deserialized.get("x").unwrap().get("w").unwrap(), 240);
        assert_eq!(deserialized.get("x").unwrap().get("d").unwrap(), 12.7);
    }

    #[test]
    fn test_builder() {
        let key = Key([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ]);
        let file_blob_id = BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap();
        let thumb_blob_id = BlobId::from_str("abcdef0123456789abcdef0123456789").unwrap();
        let msg = FileMessage::builder(file_blob_id.clone(), key.clone(), "image/jpeg", 2048)
            .thumbnail(thumb_blob_id.clone(), "image/png")
            .file_name("hello.jpg")
            .description(String::from("An image file"))
            .rendering_type(RenderingType::Media)
            .build()
            .unwrap();

        assert_eq!(msg.file_blob_id, file_blob_id);
        assert_eq!(msg.file_media_type, "image/jpeg");
        assert_eq!(msg.thumbnail_blob_id, Some(thumb_blob_id));
        assert_eq!(msg.thumbnail_media_type, Some("image/png".into()));
        assert_eq!(msg.blob_encryption_key, key);
        assert_eq!(msg.file_name, Some("hello.jpg".to_string()));
        assert_eq!(msg.file_size_bytes, 2048);
        assert_eq!(msg.description, Some("An image file".to_string()));
        assert_eq!(msg.rendering_type, RenderingType::Media);
        assert_eq!(msg.legacy_rendering_type, 1);
    }
}
