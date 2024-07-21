use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
    time::Duration,
};

use crypto_box::SecretKey;
use crypto_secretbox::Nonce;
use data_encoding::HEXLOWER_PERMISSIVE;
use reqwest::Client;

use crate::{
    cache::PublicKeyCache,
    connection::{blob_download, blob_upload, send_e2e, send_simple, Recipient},
    crypto::{
        encrypt, encrypt_file_msg, encrypt_image_msg, encrypt_raw, EncryptedMessage, RecipientKey,
    },
    errors::{ApiBuilderError, ApiError, ApiOrCacheError, CryptoError},
    lookup::{
        lookup_capabilities, lookup_credits, lookup_id, lookup_pubkey, Capabilities,
        LookupCriterion,
    },
    receive::IncomingMessage,
    types::{BlobId, FileMessage, MessageType},
    MSGAPI_URL,
};

fn make_reqwest_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
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
        /// *Note:* It is strongly recommended that you cache the public keys to avoid
        /// querying the API for each message. To simplify this, the
        /// `lookup_pubkey_with_cache` method can be used instead.
        pub async fn lookup_pubkey(&self, id: &str) -> Result<RecipientKey, ApiError> {
            lookup_pubkey(
                &self.client,
                self.endpoint.borrow(),
                &self.id,
                id,
                &self.secret,
            )
            .await
        }

        /// Fetch the recipient public key for the specified Threema ID and store it
        /// in the [`PublicKeyCache`].
        ///
        /// For the end-to-end encrypted mode, you need the public key of the recipient
        /// in order to encrypt a message. While it's best to obtain this directly from
        /// the recipient (extract it from the QR code), this may not be convenient,
        /// and therefore you can also look up the key associated with a given ID from
        /// the server.
        pub async fn lookup_pubkey_with_cache<C>(
            &self,
            id: &str,
            public_key_cache: &C,
        ) -> Result<RecipientKey, ApiOrCacheError<C::Error>>
        where
            C: PublicKeyCache,
        {
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

        /// Look up a Threema ID in the directory.
        ///
        /// An ID can be looked up either by a phone number or an e-mail
        /// address, in plaintext or hashed form. You can specify one of those
        /// criteria using the [`LookupCriterion`](enum.LookupCriterion.html)
        /// enum.
        pub async fn lookup_id(&self, criterion: &LookupCriterion) -> Result<String, ApiError> {
            lookup_id(
                &self.client,
                self.endpoint.borrow(),
                criterion,
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
        pub async fn lookup_capabilities(&self, id: &str) -> Result<Capabilities, ApiError> {
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
    id: String,
    secret: String,
    endpoint: Cow<'static, str>,
    client: Client,
}

impl SimpleApi {
    /// Initialize the simple API with the Gateway ID and the Gateway Secret.
    pub(crate) fn new<I: Into<String>, S: Into<String>>(
        endpoint: Cow<'static, str>,
        id: I,
        secret: S,
        client: Client,
    ) -> Self {
        SimpleApi {
            id: id.into(),
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
    pub async fn send(&self, to: &Recipient<'_>, text: &str) -> Result<String, ApiError> {
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
    id: String,
    secret: String,
    private_key: SecretKey,
    endpoint: Cow<'static, str>,
    client: Client,
}

impl E2eApi {
    /// Initialize the simple API with the Gateway ID, the Gateway Secret and
    /// the Private Key.
    pub(crate) fn new<I: Into<String>, S: Into<String>>(
        endpoint: Cow<'static, str>,
        id: I,
        secret: S,
        private_key: SecretKey,
        client: Client,
    ) -> Self {
        E2eApi {
            id: id.into(),
            secret: secret.into(),
            private_key,
            endpoint,
            client,
        }
    }

    /// Encrypt a text message for the specified recipient public key.
    pub fn encrypt_text_msg(
        &self,
        text: &str,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        let data = text.as_bytes();
        let msgtype = MessageType::Text;
        encrypt(data, msgtype, &recipient_key.0, &self.private_key)
    }

    /// Encrypt an image message for the specified recipient public key.
    ///
    /// Before calling this function, you need to encrypt the image data (JPEG
    /// format) with [`encrypt_raw`](struct.E2eApi.html#method.encrypt_raw) and
    /// upload the ciphertext to the blob server.
    ///
    /// The image size needs to be specified in bytes. Note that the size is
    /// only used for download size displaying purposes and has no security
    /// implications.
    pub fn encrypt_image_msg(
        &self,
        blob_id: &BlobId,
        img_size_bytes: u32,
        image_data_nonce: &Nonce,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        encrypt_image_msg(
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
    pub fn encrypt_file_msg(
        &self,
        msg: &FileMessage,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        encrypt_file_msg(msg, &recipient_key.0, &self.private_key)
    }

    /// Encrypt an arbitrary message for the specified recipient public key.
    ///
    /// The encrypted data will include PKCS#7 style random padding.
    ///
    /// Note: In almost all cases you should use [`encrypt_text_msg`],
    /// [`encrypt_file_msg`] or [`encrypt_image_msg`] instead.
    ///
    /// [`encrypt_text_msg`]: Self::encrypt_text_msg
    /// [`encrypt_file_msg`]: Self::encrypt_file_msg
    /// [`encrypt_image_msg`]: Self::encrypt_image_msg
    pub fn encrypt(
        &self,
        raw_data: &[u8],
        msgtype: MessageType,
        recipient_key: &RecipientKey,
    ) -> Result<EncryptedMessage, CryptoError> {
        encrypt(raw_data, msgtype, &recipient_key.0, &self.private_key)
    }

    /// Encrypt raw bytes for the specified recipient public key.
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
    /// you're unsure what value to use, set the flag to `false`.
    ///
    /// Cost: 1 credit.
    pub async fn send(
        &self,
        to: &str,
        message: &EncryptedMessage,
        delivery_receipts: bool,
    ) -> Result<String, ApiError> {
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

    /// Used for testing purposes. Not intended to be called by end users.
    #[doc(hidden)]
    pub async fn send_with_params(
        &self,
        to: &str,
        message: &EncryptedMessage,
        delivery_receipts: bool,
        additional_params: HashMap<String, String>,
    ) -> Result<String, ApiError> {
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
    pub fn decode_incoming_message(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<IncomingMessage, ApiError> {
        IncomingMessage::from_urlencoded_bytes(bytes, &self.secret)
    }

    /// Decrypt an [`IncomingMessage`] using the provided public key and our
    /// own private key.
    ///
    /// The format of the returned decrypted message bytes is documented at
    /// <https://gateway.threema.ch/de/developer/e2e>.
    pub fn decrypt_incoming_message(
        &self,
        message: &IncomingMessage,
        recipient_key: &RecipientKey,
    ) -> Result<Vec<u8>, CryptoError> {
        message.decrypt_box(&recipient_key.0, &self.private_key)
    }
}

/// A convenient way to set up the API object.
///
/// # Examples
///
/// ## Simple API
///
/// ```
/// use threema_gateway::{ApiBuilder, SimpleApi};
///
/// let gateway_id = "*3MAGWID";
/// let api_secret = "hihghrg98h00ghrg";
///
/// let api: SimpleApi = ApiBuilder::new(gateway_id, api_secret).into_simple();
/// ```
///
/// ## E2E API
///
/// ```
/// use threema_gateway::{ApiBuilder, E2eApi};
///
/// let gateway_id = "*3MAGWID";
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
    pub id: String,
    pub secret: String,
    pub private_key: Option<SecretKey>,
    pub endpoint: Cow<'static, str>,
    pub client: Option<Client>,
}

impl ApiBuilder {
    /// Initialize the ApiBuilder with the Gateway ID and the Gateway Secret.
    pub fn new<I: Into<String>, S: Into<String>>(id: I, secret: S) -> Self {
        ApiBuilder {
            id: id.into(),
            secret: secret.into(),
            private_key: None,
            endpoint: Cow::Borrowed(MSGAPI_URL),
            client: None,
        }
    }

    /// Set a custom API endpoint.
    ///
    /// The API endpoint should be a HTTPS URL without trailing slash.
    pub fn with_custom_endpoint<E: Into<Cow<'static, str>>>(mut self, endpoint: E) -> Self {
        let endpoint = endpoint.into();
        debug!("Using custom endpoint: {}", endpoint);
        if !(endpoint.starts_with("http:") || endpoint.starts_with("https:")) {
            warn!("Custom endpoint seems invalid!");
        }
        self.endpoint = endpoint;
        self
    }

    /// Set a custom reqwest [`Client`][reqwest::Client] that will be re-used
    /// for all connections.
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Return a [`SimpleAPI`](struct.SimpleApi.html) instance.
    pub fn into_simple(self) -> SimpleApi {
        SimpleApi::new(
            self.endpoint,
            self.id,
            self.secret,
            self.client.unwrap_or_else(make_reqwest_client),
        )
    }

    /// Set the private key. Only needed for E2e mode.
    pub fn with_private_key(mut self, private_key: SecretKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Set the private key from a byte slice. Only needed for E2e mode.
    pub fn with_private_key_bytes(mut self, private_key: &[u8]) -> Result<Self, ApiBuilderError> {
        let private_key = SecretKey::from_slice(private_key).map_err(|e| {
            ApiBuilderError::InvalidKey(format!("Invalid libsodium private key: {e}"))
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
                .map_err(|e| {
                    let msg = format!("Could not decode private key hex string: {}", e);
                    ApiBuilderError::InvalidKey(msg)
                })?;
        self.with_private_key_bytes(&private_key_bytes)
    }

    /// Return a [`E2eAPI`](struct.SimpleApi.html) instance.
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
