use std::{
    borrow::{Borrow as _, Cow},
    collections::HashMap,
    time::Duration,
};

use crypto_box::{PublicKey, SecretKey};
use crypto_secretbox::Nonce;
use data_encoding::HEXLOWER_PERMISSIVE;
use log::{debug, warn};
use reqwest::Client;

use crate::{
    MSGAPI_URL,
    cache::PublicKeyCache,
    connection::{
        BulkE2eMessage, BulkE2eMessageSendStatus, Recipient, blob_download, blob_upload, send_e2e,
        send_e2e_bulk, send_simple,
    },
    crypto::{EncryptedMessage, RecipientKey, encrypt, encrypt_raw},
    errors::{ApiBuilderError, ApiError, ApiOrCacheError, CryptoError},
    lookup::{
        BulkIdentityPublicKey, Capabilities, LookupCriterion, lookup_capabilities, lookup_credits,
        lookup_id, lookup_ids_bulk, lookup_pubkey, lookup_pubkeys_bulk,
    },
    protocol::{
        BlobId, MessageId, ThreemaId,
        e2e::{E2eMessage, MessageType, file::FileMessage},
    },
};
#[cfg(feature = "receive")]
use crate::{errors::CryptoOrMessageDecodeError, receive::IncomingMessage};

fn make_reqwest_client() -> Client {
    Client::builder()
        .timeout(Duration::from_mins(2))
        .user_agent(crate::SDK_USER_AGENT)
        .build()
        .expect("Could not build client")
}

/// Implement methods available on both the simple and the e2e API objects.
macro_rules! impl_common_functionality {
    () => {
        /// Fetch the recipient public key for the specified Threema ID.
        ///
        /// For the end-to-end encrypted mode, you need the public key of the recipient
        /// in order to encrypt a message. While it's best to obtain this directly from
        /// the recipient (extract it from the QR code), this may not be convenient,
        /// and therefore you can also look up the key associated with a given ID from
        /// the server.
        ///
        /// **Note:** It is strongly recommended that you cache the public keys to avoid
        /// querying the API for each message. To simplify this, the
        /// `lookup_pubkey_with_cache` method can be used instead.
        pub async fn lookup_pubkey(&self, id: &ThreemaId) -> Result<RecipientKey, ApiError> {
            lookup_pubkey(
                &self.client,
                self.endpoint.borrow(),
                &self.id,
                id,
                &self.secret,
            )
            .await
        }

        /// Obtain the recipient public key for the specified Threema ID
        /// from the [`PublicKeyCache`] or the network.
        ///
        /// On cache miss, the public key is fetched from the server
        /// (see [`Self::lookup_pubkey`]) and stored in the cache.
        pub async fn lookup_pubkey_with_cache<C>(
            &self,
            id: &ThreemaId,
            public_key_cache: &C,
        ) -> Result<RecipientKey, ApiOrCacheError<C::Error>>
        where
            C: PublicKeyCache,
        {
            let cached_key = public_key_cache
                .load(id)
                .await
                .map_err(ApiOrCacheError::CacheError)?;

            if let Some(pubkey) = cached_key {
                // Cache hit
                Ok(pubkey)
            } else {
                // Cache miss
                let pubkey = self
                    .lookup_pubkey(id)
                    .await
                    .map_err(ApiOrCacheError::ApiError)?;
                public_key_cache
                    .store(id, &pubkey)
                    .await
                    .map_err(ApiOrCacheError::CacheError)?;
                Ok(pubkey)
            }
        }

        /// Lookup multiple public keys at once.
        ///
        /// This is like `lookup_pubkey`, but you can look up public keys for
        /// multiple IDs in a single request.
        pub async fn lookup_pubkeys_bulk(
            &self,
            ids: &[ThreemaId],
        ) -> Result<HashMap<ThreemaId, RecipientKey>, ApiError> {
            lookup_pubkeys_bulk(
                &self.client,
                self.endpoint.borrow(),
                &self.id,
                ids,
                &self.secret,
            )
            .await
        }

        /// Look up a Threema ID in the directory.
        ///
        /// An ID can be looked up either by a phone number or an e-mail address, in plaintext or hashed form.
        /// You can specify one of those criteria using the [`LookupCriterion`] enum.
        pub async fn lookup_id(&self, criterion: &LookupCriterion) -> Result<ThreemaId, ApiError> {
            lookup_id(
                &self.client,
                self.endpoint.borrow(),
                criterion,
                &self.id,
                &self.secret,
            )
            .await
        }

        /// Look up multiple IDs at once.
        ///
        /// This is like `lookup_id`, but you can look up multiple IDs in a
        /// single request.
        ///
        /// **Note:** The use of this endpoint is restricted and requires manual
        /// approval. Please contact the Threema support team directly if you
        /// would like to use this feature.
        pub async fn lookup_ids_bulk(
            &self,
            criteria: &[&LookupCriterion],
        ) -> Result<Vec<BulkIdentityPublicKey>, ApiError> {
            lookup_ids_bulk(
                &self.client,
                self.endpoint.borrow(),
                criteria,
                &self.id,
                &self.secret,
            )
            .await
        }

        /// Look up the capabilities of a certain Threema ID.
        ///
        /// Before you send a file to a Threema ID using the blob upload (+file
        /// message), you may want to check whether the recipient uses a
        /// Threema version that supports receiving files. The receiver may be
        /// using an old version, or a platform where file reception is not
        /// supported.
        pub async fn lookup_capabilities(&self, id: &ThreemaId) -> Result<Capabilities, ApiError> {
            lookup_capabilities(
                &self.client,
                self.endpoint.borrow(),
                &self.id,
                id,
                &self.secret,
            )
            .await
        }

        /// Look up a remaining gateway credits.
        pub async fn lookup_credits(&self) -> Result<i64, ApiError> {
            lookup_credits(&self.client, self.endpoint.borrow(), &self.id, &self.secret).await
        }
    };
}

/// Struct to talk to the simple API (without end-to-end encryption).
#[derive(Debug, Clone)]
pub struct SimpleApi {
    id: ThreemaId,
    secret: String,
    endpoint: Cow<'static, str>,
    client: Client,
}

impl SimpleApi {
    /// Initialize the simple API with the Gateway ID and the Gateway Secret.
    pub(crate) fn new<S: Into<String>>(
        endpoint: Cow<'static, str>,
        id: ThreemaId,
        secret: S,
        client: Client,
    ) -> Self {
        SimpleApi {
            id,
            secret: secret.into(),
            endpoint,
            client,
        }
    }

    /// Send a message to the specified recipient in basic mode.
    ///
    /// Note that this mode of sending messages does not provide end-to-end
    /// encryption, only transport encryption between your host and the Threema
    /// Gateway server.
    ///
    /// Cost: 1 credit.
    pub async fn send(&self, to: &Recipient<'_>, text: &str) -> Result<MessageId, ApiError> {
        send_simple(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            to,
            &self.secret,
            text,
        )
        .await
    }

    impl_common_functionality!();
}

/// Struct to talk to the E2E API (with end-to-end encryption).
#[derive(Debug, Clone)]
pub struct E2eApi {
    id: ThreemaId,
    secret: String,
    private_key: SecretKey,
    endpoint: Cow<'static, str>,
    client: Client,
}

impl E2eApi {
    /// Initialize the simple API with the Gateway ID, the Gateway Secret and
    /// the Private Key.
    pub(crate) fn new<S: Into<String>>(
        endpoint: Cow<'static, str>,
        id: ThreemaId,
        secret: S,
        private_key: SecretKey,
        client: Client,
    ) -> Self {
        E2eApi {
            id,
            secret: secret.into(),
            private_key,
            endpoint,
            client,
        }
    }

    /// Encode and encrypt an [`E2eMessage`] for the specified recipient public key.
    pub fn encode_and_encrypt(
        &self,
        msg: &E2eMessage,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        let encoded = msg.encode();
        encrypt(
            &encoded.message_bytes,
            encoded.message_type,
            &recipient_key.0,
            &self.private_key,
        )
    }

    /// Encode and encrypt a text message for the specified recipient public key.
    #[deprecated(
        since = "0.20.0",
        note = "Use `encode_and_encrypt` with `E2eMessage::Text` instead"
    )]
    pub fn encrypt_text_msg(
        &self,
        text: &str,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        let data = text.as_bytes();
        encrypt(data, MessageType::Text, &recipient_key.0, &self.private_key)
    }

    /// Encode and encrypt an image message for the specified recipient public key.
    ///
    /// Before calling this function, you need to encrypt the image data (JPEG
    /// format) with [`encrypt_raw`](struct.E2eApi.html#method.encrypt_raw) and
    /// upload the ciphertext to the blob server.
    ///
    /// The image size needs to be specified in bytes. Note that the size is
    /// only used for download size displaying purposes and has no security
    /// implications.
    #[deprecated(
        since = "0.20.0",
        note = "The image message type is deprecated. Use file messages with appropriate rendering type instead."
    )]
    #[expect(
        deprecated,
        reason = "Deprecated method delegates to deprecated function"
    )]
    pub fn encrypt_image_msg(
        &self,
        blob_id: &BlobId,
        img_size_bytes: u32,
        image_data_nonce: &Nonce,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        crate::crypto::encrypt_image_msg(
            blob_id,
            img_size_bytes,
            image_data_nonce,
            &recipient_key.0,
            &self.private_key,
        )
    }

    /// Encrypt a file message for the specified recipient public key.
    ///
    /// To construct a [`FileMessage`], use [`FileMessageBuilder`].
    ///
    /// [`FileMessage`]: struct.FileMessage.html
    /// [`FileMessageBuilder`]: struct.FileMessageBuilder.html
    #[deprecated(
        since = "0.20.0",
        note = "Use `encode_and_encrypt` with `E2eMessage::File` instead"
    )]
    pub fn encrypt_file_msg(
        &self,
        msg: &FileMessage,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        self.encode_and_encrypt(&E2eMessage::File(msg.clone()), recipient_key)
    }

    /// Encrypt arbitrary pre-encoded message bytes (excluding the message type byte) for the specified
    /// recipient public key.
    ///
    /// **Note:** In almost all cases you should use [`encode_and_encrypt`] instead.
    ///
    /// [`encode_and_encrypt`]: Self::encode_and_encrypt
    pub fn encrypt(
        &self,
        raw_data: &[u8],
        msgtype: MessageType,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        encrypt(raw_data, msgtype, &recipient_key.0, &self.private_key)
    }

    /// Encrypt raw bytes for the specified recipient public key.
    #[deprecated(
        since = "0.20.0",
        note = "Only needed for image messages, which are deprecated. Use file messages with appropriate rendering type instead."
    )]
    pub fn encrypt_raw(
        &self,
        raw_data: &[u8],
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        encrypt_raw(raw_data, &recipient_key.0, &self.private_key)
    }

    /// Send an encrypted E2E message to the specified Threema ID.
    ///
    /// If `delivery_receipts` is set to `false`, then the recipient's device will
    /// be instructed not to send any delivery receipts. This can be useful for
    /// one-way communication where the delivery receipt will be discarded. If
    /// you're unsure what value to use, set the flag to `true`.
    ///
    /// Cost: 1 credit.
    pub async fn send(
        &self,
        to: &ThreemaId,
        message: &EncryptedMessage,
        delivery_receipts: bool,
    ) -> Result<MessageId, ApiError> {
        send_e2e(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            to,
            &self.secret,
            &message.nonce,
            &message.ciphertext,
            delivery_receipts,
            None,
        )
        .await
    }

    /// Send multiple encrypted E2E messages.
    ///
    /// If `same_message_id` is set to `true`, then all messages sent will
    /// share the same message ID. This is a feature that is only relevant for
    /// group messaging. If unsure, set this to `false`.
    ///
    /// **Note:** This endpoint is rate-limited. You may send a maximum of
    /// 1000 messages in a single bulk request and will get an
    /// [`ApiError::RateLimitReached`] when the rate limit is exceeded.
    ///
    /// Cost: 1 credit per message.
    pub async fn send_bulk(
        &self,
        messages: &[&BulkE2eMessage],
        same_message_id: bool,
    ) -> Result<Vec<BulkE2eMessageSendStatus>, ApiError> {
        send_e2e_bulk(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            &self.secret,
            messages,
            same_message_id,
        )
        .await
    }

    /// Used for testing purposes. Not intended to be called by end users.
    #[doc(hidden)]
    pub async fn send_with_params(
        &self,
        to: &ThreemaId,
        message: &EncryptedMessage,
        delivery_receipts: bool,
        additional_params: HashMap<String, String>,
    ) -> Result<MessageId, ApiError> {
        send_e2e(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            to,
            &self.secret,
            &message.nonce,
            &message.ciphertext,
            delivery_receipts,
            Some(additional_params),
        )
        .await
    }

    impl_common_functionality!();

    /// Upload encrypted data to the blob server.
    ///
    /// If `persist` is set to `true`, then the blob will not be deleted
    /// after a client has downloaded it and marked it as done. Use when
    /// distributing the same blob to multiple clients.
    ///
    /// Cost: 1 credit.
    pub async fn blob_upload(
        &self,
        data: &EncryptedMessage,
        persist: bool,
    ) -> Result<BlobId, ApiError> {
        blob_upload(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            &self.secret,
            &data.ciphertext,
            persist,
            None,
        )
        .await
    }

    /// Used for testing purposes. Not intended to be called by end users.
    #[doc(hidden)]
    pub async fn blob_upload_with_params(
        &self,
        data: &EncryptedMessage,
        persist: bool,
        additional_params: HashMap<String, String>,
    ) -> Result<BlobId, ApiError> {
        blob_upload(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            &self.secret,
            &data.ciphertext,
            persist,
            Some(additional_params),
        )
        .await
    }

    /// Upload raw data to the blob server.
    ///
    /// If `persist` is set to `true`, then the blob will not be deleted
    /// after a client has downloaded it and marked it as done. Use when
    /// distributing the same blob to multiple clients.
    ///
    /// Cost: 1 credit.
    pub async fn blob_upload_raw(&self, data: &[u8], persist: bool) -> Result<BlobId, ApiError> {
        blob_upload(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            &self.secret,
            data,
            persist,
            None,
        )
        .await
    }

    /// Used for testing purposes. Not intended to be called by end users.
    #[doc(hidden)]
    pub async fn blob_upload_raw_with_params(
        &self,
        data: &[u8],
        persist: bool,
        additional_params: HashMap<String, String>,
    ) -> Result<BlobId, ApiError> {
        blob_upload(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            &self.secret,
            data,
            persist,
            Some(additional_params),
        )
        .await
    }

    /// Download a blob from the blob server and return the encrypted bytes.
    ///
    /// Cost: 0 credits.
    pub async fn blob_download(&self, blob_id: &BlobId) -> Result<Vec<u8>, ApiError> {
        blob_download(
            &self.client,
            self.endpoint.borrow(),
            &self.id,
            &self.secret,
            blob_id,
        )
        .await
    }

    /// Deserialize an incoming Threema Gateway message in
    /// `application/x-www-form-urlencoded` format.
    ///
    /// This will validate the MAC. If the MAC is invalid,
    /// [`ApiError::InvalidMac`] will be returned.
    #[cfg(feature = "receive")]
    pub fn decode_incoming_message<B: AsRef<[u8]>>(
        &self,
        bytes: B,
    ) -> Result<IncomingMessage, ApiError> {
        IncomingMessage::from_urlencoded_bytes(bytes, &self.secret)
    }

    /// Decrypt an [`IncomingMessage`] using the provided public key and our own private key and return the
    /// raw bytes.
    ///
    /// The format of the returned decrypted message bytes is documented at
    /// <https://gateway.threema.ch/de/developer/e2e>.
    ///
    /// **Note:** You should probably not use this directly, but instead use
    /// [`E2eApi::decrypt_and_decode_incoming_message`]!
    #[cfg(feature = "receive")]
    pub fn decrypt_incoming_message(
        &self,
        message: &IncomingMessage,
        recipient_key: &RecipientKey,
    ) -> Result<Vec<u8>, CryptoError> {
        message.decrypt_box(&recipient_key.0, &self.private_key)
    }

    /// Decrypt and decode an [`IncomingMessage`] using the provided public key and our own private key.
    #[cfg(feature = "receive")]
    pub fn decrypt_and_decode_incoming_message(
        &self,
        message: &IncomingMessage,
        recipient_key: &RecipientKey,
    ) -> Result<E2eMessage, CryptoOrMessageDecodeError> {
        let decrypted_bytes = self.decrypt_incoming_message(message, recipient_key)?;
        let e2e_message = E2eMessage::decode_from_decrypted_bytes(&decrypted_bytes)?;
        Ok(e2e_message)
    }

    /// Return own public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.private_key.public_key()
    }
}

/// A convenient way to set up the API object.
///
/// # Examples
///
/// ## Simple API
///
/// ```
/// use threema_gateway::{ApiBuilder, SimpleApi, ThreemaId};
///
/// let gateway_id = ThreemaId::try_from("*3MAGWID").unwrap();
/// let api_secret = "hihghrg98h00ghrg";
///
/// let api: SimpleApi = ApiBuilder::new(gateway_id, api_secret).into_simple();
/// ```
///
/// ## E2E API
///
/// ```
/// use threema_gateway::{ApiBuilder, E2eApi, ThreemaId};
///
/// let gateway_id = ThreemaId::try_from("*3MAGWID").unwrap();
/// let api_secret = "hihghrg98h00ghrg";
/// let private_key = "998730fbcac1c57dbb181139de41d12835b3fae6af6acdf6ce91670262e88453";
///
/// let api: E2eApi = ApiBuilder::new(gateway_id, api_secret)
///                              .with_private_key_str(private_key)
///                              .and_then(|builder| builder.into_e2e())
///                              .unwrap();
/// ```
#[derive(Debug)]
pub struct ApiBuilder {
    id: ThreemaId,
    secret: String,
    private_key: Option<SecretKey>,
    endpoint: Cow<'static, str>,
    client: Option<Client>,
}

impl ApiBuilder {
    /// Initialize the `ApiBuilder` with the Gateway ID and the Gateway Secret.
    pub fn new<S: Into<String>>(id: ThreemaId, secret: S) -> Self {
        ApiBuilder {
            id,
            secret: secret.into(),
            private_key: None,
            endpoint: Cow::Borrowed(MSGAPI_URL),
            client: None,
        }
    }

    /// Set a custom API endpoint.
    ///
    /// The API endpoint should be a HTTPS URL without trailing slash.
    #[must_use]
    pub fn with_custom_endpoint<E: Into<Cow<'static, str>>>(mut self, endpoint: E) -> Self {
        let endpoint = endpoint.into();
        debug!("Using custom endpoint: {endpoint}");
        if !(endpoint.starts_with("http:") || endpoint.starts_with("https:")) {
            warn!("Custom endpoint seems invalid!");
        }
        self.endpoint = endpoint;
        self
    }

    /// Set a custom reqwest [`Client`][reqwest::Client] that will be re-used
    /// for all connections.
    #[must_use]
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Return a [`SimpleApi`] instance.
    pub fn into_simple(self) -> SimpleApi {
        SimpleApi::new(
            self.endpoint,
            self.id,
            self.secret,
            self.client.unwrap_or_else(make_reqwest_client),
        )
    }

    /// Set the private key. Only needed for E2e mode.
    #[must_use]
    pub fn with_private_key(mut self, private_key: SecretKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Set the private key from a byte slice. Only needed for E2e mode.
    pub fn with_private_key_bytes(mut self, private_key: &[u8]) -> Result<Self, ApiBuilderError> {
        let private_key = SecretKey::from_slice(private_key).map_err(|error| {
            ApiBuilderError::InvalidKey(format!("Invalid libsodium private key: {error}"))
        })?;
        self.private_key = Some(private_key);
        Ok(self)
    }

    /// Set the private key from a hex-encoded string reference. Only needed
    /// for E2e mode.
    pub fn with_private_key_str(self, private_key: &str) -> Result<Self, ApiBuilderError> {
        let private_key_bytes =
            HEXLOWER_PERMISSIVE
                .decode(private_key.as_bytes())
                .map_err(|error| {
                    let msg = format!("Could not decode private key hex string: {error}");
                    ApiBuilderError::InvalidKey(msg)
                })?;
        self.with_private_key_bytes(&private_key_bytes)
    }

    /// Return a [`E2eApi`] instance.
    ///
    /// This will fail if no private key was set.
    pub fn into_e2e(self) -> Result<E2eApi, ApiBuilderError> {
        match self.private_key {
            Some(key) => Ok(E2eApi::new(
                self.endpoint,
                self.id,
                self.secret,
                key,
                self.client.unwrap_or_else(make_reqwest_client),
            )),
            None => Err(ApiBuilderError::MissingKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    mod public_key {
        use super::*;

        #[rstest]
        #[case(
            "788433c173964f725b83d33676c5c25d623783ad22a3d50a8573bf5d2a4e6bac",
            "caea70eb4fde41591d6454006322d65b8c57a6b40e2292c87954a539bc8e326f"
        )]
        #[case(
            "ecf5e324131eab54d4b35d912593fe946b889309f77c2e6e8eec1071a600b468",
            "820e358d85606e36c306548da4f25da571a39715959bb796d6b4ea10f9652b59"
        )]
        fn correct_public_key(#[case] private: String, #[case] public: String) {
            let private_bytes = data_encoding::HEXLOWER.decode(private.as_bytes()).unwrap();
            let public_bytes = data_encoding::HEXLOWER.decode(public.as_bytes()).unwrap();

            let api = E2eApi::new(
                "endpoint".into(),
                "HELOWRLD".try_into().unwrap(),
                "fakescrt",
                SecretKey::from_slice(&private_bytes).unwrap(),
                Client::new(),
            );
            assert_eq!(
                api.public_key(),
                PublicKey::from_slice(&public_bytes).unwrap()
            );
        }
    }
}
