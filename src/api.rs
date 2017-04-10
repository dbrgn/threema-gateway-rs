use data_encoding::hex;
use sodiumoxide::crypto::box_::SecretKey;

use ::errors::ApiBuilderError;

/// Struct to talk to the simple API (without end-to-end encryption).
pub struct SimpleApi {
    id: String,
    secret: String,
}

impl SimpleApi {
    /// Initialize the simple API with the Gateway ID and the Gateway Secret.
    pub fn new<I: Into<String>, S: Into<String>>(id: I, secret: S) -> Self {
        return SimpleApi { id: id.into(), secret: secret.into() }
    }
}

/// Struct to talk to the E2E API (with end-to-end encryption).
pub struct E2eApi {
    id: String,
    secret: String,
    private_key: SecretKey,
}

impl E2eApi {
    /// Initialize the simple API with the Gateway ID, the Gateway Secret and
    /// the Private Key.
    pub fn new<I: Into<String>, S: Into<String>>(id: I, secret: S, private_key: SecretKey) -> Self {
        return E2eApi {
            id: id.into(),
            secret: secret.into(),
            private_key: private_key,
        }
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
/// let gateway_secret = "hihghrg98h00ghrg";
/// 
/// let api: SimpleApi = ApiBuilder::new(gateway_id, gateway_secret).as_simple();
/// ```
/// 
/// ## E2E API
/// 
/// ```
/// use threema_gateway::{ApiBuilder, E2eApi};
/// 
/// let gateway_id = "*3MAGWID";
/// let gateway_secret = "hihghrg98h00ghrg";
/// let private_key = "998730fbcac1c57dbb181139de41d12835b3fae6af6acdf6ce91670262e88453";
/// 
/// let api: E2eApi = ApiBuilder::new(gateway_id, gateway_secret)
///                              .with_private_key_str(private_key)
///                              .and_then(|builder| builder.as_e2e())
///                              .unwrap();
/// ```
pub struct ApiBuilder {
    pub id: String,
    pub secret: String,
    pub private_key: Option<SecretKey>,
}

impl ApiBuilder {
    /// Initialize the ApiBuilder with the Gateway ID and the Gateway Secret.
    pub fn new<I: Into<String>, S: Into<String>>(id: I, secret: S) -> Self {
        ApiBuilder {
            id: id.into(),
            secret: secret.into(),
            private_key: None,
        }
    }

    /// Return a [`SimpleAPI`](struct.SimpleApi.html) instance.
    pub fn as_simple(self) -> SimpleApi {
        SimpleApi::new(self.id, self.secret)
    }

    /// Set the private key. Only needed for E2e mode.
    pub fn with_private_key(mut self, private_key: SecretKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Set the private key from a byte slice. Only needed for E2e mode.
    pub fn with_private_key_bytes(mut self, private_key: &[u8]) -> Result<Self, ApiBuilderError> {
        let private_key = SecretKey::from_slice(private_key)
            .ok_or(ApiBuilderError::InvalidKey("Invalid libsodium private key".into()))?;
        self.private_key = Some(private_key);
        Ok(self)
    }

    /// Set the private key from a hex-encoded string reference. Only needed
    /// for E2e mode.
    pub fn with_private_key_str(self, private_key: &str) -> Result<Self, ApiBuilderError> {
        // TODO: to_uppercase() allocates a new String. This is necessary because
        // hex decoding only accepts uppercase letters. Would be nice to get rid of
        // that.
        let private_key_bytes = hex::decode(private_key.to_uppercase().as_bytes())
            .map_err(|e| {
                let msg = format!("Could not decode private key hex string: {}", e);
                ApiBuilderError::InvalidKey(msg)
            })?;
        self.with_private_key_bytes(&private_key_bytes)
    }

    /// Return a [`E2eAPI`](struct.SimpleApi.html) instance.
    pub fn as_e2e(self) -> Result<E2eApi, ApiBuilderError> {
        match self.private_key {
            Some(key) => Ok(E2eApi::new(self.id, self.secret, key)),
            None => Err(ApiBuilderError::MissingKey),
        }
    }
}
