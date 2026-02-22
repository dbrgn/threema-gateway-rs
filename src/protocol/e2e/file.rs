//! File message related types.

use log::warn;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{Key, protocol::BlobId};

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
    /// Another rendering type (unknown)
    Other(u8),
}

impl From<RenderingType> for u8 {
    fn from(val: RenderingType) -> Self {
        match val {
            RenderingType::File => 0,
            RenderingType::Media => 1,
            RenderingType::Sticker => 2,
            RenderingType::Other(value) => value,
        }
    }
}

impl Serialize for RenderingType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8((*self).into())
    }
}

impl<'de> Deserialize<'de> for RenderingType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        match value {
            0 => Ok(RenderingType::File),
            1 => Ok(RenderingType::Media),
            2 => Ok(RenderingType::Sticker),
            other => Ok(RenderingType::Other(other)),
        }
    }
}

/// A file message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileMessage {
    /// Blob ID of encrypted file data on blob server
    #[serde(rename = "b")]
    pub file_blob_id: BlobId,
    /// Media type (aka MIME type) of the file
    #[serde(rename = "m")]
    pub file_media_type: String,

    /// Blob ID of encrypted thumbnail data on blob server
    #[serde(rename = "t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_blob_id: Option<BlobId>,
    /// Media type (aka MIME type) of the thumbnail
    #[serde(rename = "p")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_media_type: Option<String>,

    /// Symmetric encryption key used for blobs
    #[serde(rename = "k")]
    pub blob_encryption_key: Key,

    /// File name
    #[serde(rename = "n")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// File size in bytes
    #[serde(rename = "s")]
    pub file_size_bytes: u32,
    /// Caption text
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Rendering type
    ///
    /// This type determines how to render the file in a chat.
    #[serde(rename = "j")]
    pub rendering_type: RenderingType,
    /// Legacy rendering type
    ///
    /// Set this to 1 if the rendering type is `Media` or `Sticker`, otherwise set this to 0.
    ///
    /// When receiving a file message, ignore this flag.
    #[serde(rename = "i")]
    pub legacy_rendering_type: u8,

    /// Optional additional metadata
    #[serde(rename = "x")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<FileMetadata>,
}

/// Metadata for a file message (depending on media type).
///
/// This data is intended to enhance the layout logic when rendering the file in a chat.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FileMetadata {
    /// (For image) Image is animated (e.g. an animated GIF)
    #[serde(rename = "a")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub animated: Option<bool>,
    /// (For image or video) Height in px
    #[serde(rename = "h")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// (For image or video) Width in px
    #[serde(rename = "w")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// (For video or audio) Duration in seconds
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<f32>,
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
    /// Create a new [`FileMessageBuilder`].
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
    pub fn builder<M: Into<String>>(
        file_blob_id: BlobId,
        blob_encryption_key: Key,
        media_type: M,
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

/// Errors when interacting with the [`FileMessageBuilder`].
#[derive(Debug, PartialEq, Clone, Error)]
pub enum FileMessageBuilderError {
    /// Illegal combination of fields (e.g. setting the `animated` flag on a PDF file message).
    #[error("illegal combination: {0}")]
    IllegalCombination(&'static str),
}

/// Builder for [`FileMessage`]. Instantiate through [`FileMessage::builder`].
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
    pub(crate) fn new<M: Into<String>>(
        file_blob_id: BlobId,
        blob_encryption_key: Key,
        media_type: M,
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
        self.metadata
            .as_mut()
            .expect("Cannot fail, since we assign metadata above")
    }

    /// Set a thumbnail.
    ///
    /// Before calling this function, you need to encrypt and upload the
    /// thumbnail data along with the file data (as described in
    /// [`FileMessage::builder`]).
    #[must_use]
    pub fn thumbnail<M: Into<String>>(self, blob_id: BlobId, media_type: M) -> Self {
        self.thumbnail_opt(Some((blob_id, media_type)))
    }

    /// Set a thumbnail from an Option.
    ///
    /// Before calling this function, you need to encrypt and upload the
    /// thumbnail data along with the file data (as described in
    /// [`FileMessage::builder`]).
    #[must_use]
    pub fn thumbnail_opt<M: Into<String>>(mut self, blob: Option<(BlobId, M)>) -> Self {
        if let Some((blob_id, media_type)) = blob {
            self.thumbnail_blob_id = Some(blob_id);
            self.thumbnail_media_type = Some(media_type.into());
        } else {
            self.thumbnail_blob_id = None;
            self.thumbnail_media_type = None;
        }
        self
    }

    /// Set the file name.
    ///
    /// Note that the file name will not be shown in the clients if the
    /// rendering type is not set to [`RenderingType::File`].
    #[must_use]
    pub fn file_name<F: Into<String>>(self, file_name: F) -> Self {
        self.file_name_opt(Some(file_name))
    }

    /// Set the file name from an Option.
    ///
    /// Note that the file name will not be shown in the clients if the
    /// rendering type is not set to [`RenderingType::File`].
    #[must_use]
    pub fn file_name_opt<F: Into<String>>(mut self, file_name: Option<F>) -> Self {
        self.file_name = file_name.map(Into::into);
        self
    }

    /// Set the file description / caption.
    #[must_use]
    pub fn description<D: Into<String>>(self, description: D) -> Self {
        self.description_opt(Some(description))
    }

    /// Set the file description / caption from an Option.
    #[must_use]
    pub fn description_opt<D: Into<String>>(mut self, description: Option<D>) -> Self {
        self.description = description.map(Into::into);
        self
    }

    /// Set the rendering type.
    ///
    /// See [`RenderingType`] docs for more information.
    #[must_use]
    pub fn rendering_type(mut self, rendering_type: RenderingType) -> Self {
        self.rendering_type = rendering_type;
        self
    }

    /// Mark this file message as animated.
    ///
    /// May only be used for files with rendering type [`RenderingType::Media`] or [`RenderingType::Sticker`].
    #[must_use]
    pub fn animated(mut self, animated: bool) -> Self {
        self.ensure_metadata().animated = Some(animated);
        self
    }

    /// Set the dimensions of this file message.
    ///
    /// May only be used for files with rendering type [`RenderingType::Media`] or [`RenderingType::Sticker`].
    #[must_use]
    pub fn dimensions(mut self, height: u32, width: u32) -> Self {
        let metadata = self.ensure_metadata();
        metadata.height = Some(height);
        metadata.width = Some(width);
        self
    }

    /// Set the duration (in seconds) of this file message.
    ///
    /// May only be used for audio/video files with rendering type [`RenderingType::Media`].
    #[must_use]
    pub fn duration(mut self, seconds: f32) -> Self {
        self.ensure_metadata().duration_seconds = Some(seconds);
        self
    }

    /// Create a [`FileMessage`] from this builder.
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
                warn!("Created FileMessage with rendering type Media but without metadata");
            }
        } else {
            if self.rendering_type == RenderingType::Media {
                warn!("Created FileMessage with rendering type Media but without metadata");
            }
        }

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

#[cfg(test)]
mod test {
    use std::str::FromStr as _;

    use super::*;

    #[test]
    fn serialize_to_string_minimal() {
        let key = Key::from([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ]);
        let msg = FileMessage {
            file_blob_id: BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap(),
            file_media_type: "application/pdf".parse().unwrap(),
            thumbnail_blob_id: None,
            thumbnail_media_type: None,
            blob_encryption_key: key,
            file_name: None,
            file_size_bytes: 2048,
            description: None,
            rendering_type: RenderingType::File,
            legacy_rendering_type: 0,
            metadata: None,
        };
        insta::assert_json_snapshot!(msg);
    }

    #[test]
    fn serialize_to_string_full() {
        let key = Key::from([
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ]);
        let msg = FileMessage {
            file_blob_id: BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap(),
            file_media_type: "application/pdf".parse().unwrap(),
            thumbnail_blob_id: Some(BlobId::from_str("abcdef0123456789abcdef0123456789").unwrap()),
            thumbnail_media_type: Some("image/jpeg".parse().unwrap()),
            blob_encryption_key: key,
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
        insta::assert_json_snapshot!(msg);
    }

    #[test]
    fn builder_works() {
        let key_bytes = [
            1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1,
            2, 3, 4,
        ];
        let key: Key = key_bytes.into();
        let file_blob_id = BlobId::from_str("0123456789abcdef0123456789abcdef").unwrap();
        let thumb_blob_id = BlobId::from_str("abcdef0123456789abcdef0123456789").unwrap();
        let msg = FileMessage::builder(file_blob_id.clone(), key, "image/jpeg", 2048)
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
        assert_eq!(&**msg.blob_encryption_key.as_ref(), key_bytes);
        assert_eq!(msg.file_name, Some("hello.jpg".to_owned()));
        assert_eq!(msg.file_size_bytes, 2048);
        assert_eq!(msg.description, Some("An image file".to_owned()));
        assert_eq!(msg.rendering_type, RenderingType::Media);
        assert_eq!(msg.legacy_rendering_type, 1);
    }
}
