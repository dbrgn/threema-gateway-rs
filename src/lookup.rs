//! ID and public key lookups.

use std::{collections::HashMap, fmt, str};

use crypto_box::KEY_SIZE;
use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{RecipientKey, connection::map_response_code, errors::ApiError};

type HmacSha256 = Hmac<Sha256>;

/// Different ways to look up a Threema ID in the directory.
#[derive(Debug, PartialEq)]
pub enum LookupCriterion {
    /// The phone number must be passed in E.164 format, without the leading `+`.
    Phone(String),
    /// The phone number must be passed as an HMAC-SHA256 hash of the E.164
    /// number without the leading `+`. The HMAC key is
    /// `85adf8226953f3d96cfd5d09bf29555eb955fcd8aa5ec4f9fcd869e258370723`
    /// (in hexadecimal).
    PhoneHash(String),
    /// The email address.
    Email(String),
    /// The lowercased and whitespace-trimmed email address must be hashed with
    /// HMAC-SHA256. The HMAC key is
    /// `30a5500fed9701fa6defdb610841900febb8e430881f7ad816826264ec09bad7`
    /// (in hexadecimal).
    EmailHash(String),
}

impl LookupCriterion {

    /// Return the hashed version of the lookup criterion as `String`.
    ///
    /// If the lookup criterion already contains a hash, return a copy
    /// of it. Otherwise, apply HMAC-SHA256 and return the resulting
    /// hash as hex string.
    fn hash(&self) -> Result<String, ApiError> {
        let email_key = b"\x30\xa5\x50\x0f\xed\x97\x01\xfa\x6d\xef\xdb\x61\x08\x41\x90\x0f\xeb\xb8\xe4\x30\x88\x1f\x7a\xd8\x16\x82\x62\x64\xec\x09\xba\xd7";
        let phone_key = 
        b"\x85\xad\xf8\x22\x69\x53\xf3\xd9\x6c\xfd\x5d\x09\xbf\x29\x55\x5e\xb9\x55\xfc\xd8\xaa\x5e\xc4\xf9\xfc\xd8\x69\xe2\x58\x37\x07\x23";

        let s = match self {
            Self::Phone(val) => {
                let mut hmac_state = HmacSha256::new_from_slice(phone_key)
                    .map_err(|_| ApiError::Other("Invalid api_secret".to_string()))?;
                if !val.chars().all(|c | c.is_ascii_digit()) {
                    return Err(ApiError::Other("Bad phone number format".to_string()))
                }
                hmac_state.update(val.as_bytes());
                let hash = hmac_state.finalize().into_bytes();
                HEXLOWER.encode(&hash)
            }
            Self::PhoneHash(val) => val.to_owned(),
            Self::Email(val) => {
                let mut hmac_state = HmacSha256::new_from_slice(email_key)
                    .map_err(|_| ApiError::Other("Invalid api_secret".to_string()))?;
                hmac_state.update(val.to_lowercase().trim().as_bytes());
                let hash = hmac_state.finalize().into_bytes();
                HEXLOWER.encode(&hash)
            }
            Self::EmailHash(val) => val.to_owned(),
        };
        Ok(s)
    } 
}

impl fmt::Display for LookupCriterion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LookupCriterion::Phone(n) => write!(f, "phone {}", n),
            LookupCriterion::PhoneHash(nh) => write!(f, "phone hash {}", nh),
            LookupCriterion::Email(e) => write!(f, "email {}", e),
            LookupCriterion::EmailHash(eh) => write!(f, "email hash {}", eh),
        }
    }
}

/// A struct containing flags according to the capabilities of a Threema ID.
#[derive(Debug, PartialEq)]
pub struct Capabilities {
    /// Whether the ID can receive text messages.
    pub text: bool,
    /// Whether the ID can receive image messages.
    pub image: bool,
    /// Whether the ID can receive video messages.
    pub video: bool,
    /// Whether the ID can receive audio messages.
    pub audio: bool,
    /// Whether the ID can receive file messages.
    pub file: bool,
    /// List of other capabilities this ID has.
    pub other: Vec<String>,
}

impl Capabilities {
    fn new() -> Self {
        Capabilities {
            text: false,
            image: false,
            video: false,
            audio: false,
            file: false,
            other: Vec::new(),
        }
    }
}

impl str::FromStr for Capabilities {
    type Err = ApiError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut capabilities = Capabilities::new();
        for capability in s.split(',').map(str::trim).map(str::to_lowercase) {
            match capability.as_ref() {
                "text" => capabilities.text = true,
                "image" => capabilities.image = true,
                "video" => capabilities.video = true,
                "audio" => capabilities.audio = true,
                "file" => capabilities.file = true,
                _ if !capability.is_empty() => capabilities.other.push(capability),
                _ => { /* skip empty entries */ }
            };
        }
        Ok(capabilities)
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ text: {}, image: {}, video: {}, audio: {}, file: {}",
            self.text, self.image, self.video, self.audio, self.file
        )?;
        if !self.other.is_empty() {
            write!(f, ", other: {} }}", self.other.join(","))?;
        } else {
            write!(f, " }}")?;
        }
        Ok(())
    }
}

impl Capabilities {
    /// Return whether the specified capability is present.
    pub fn can(&self, capability: &str) -> bool {
        match capability {
            "text" => self.text,
            "image" => self.image,
            "video" => self.video,
            "audio" => self.audio,
            "file" => self.file,
            _ => self.other.contains(&capability.to_lowercase()),
        }
    }
}

/// Fetch the recipient public key for the specified Threema ID.
pub(crate) async fn lookup_pubkey(
    client: &Client,
    endpoint: &str,
    our_id: &str,
    their_id: &str,
    secret: &str,
) -> Result<RecipientKey, ApiError> {
    let url = reqwest::Url::parse(endpoint)?.join("pubkeys/")?.join(their_id)?;

    debug!("Looking up public key for {}", their_id);

    // Send request
    let res = client.get(url).query(&[("from", our_id),("secret", secret)]).send().await?;
    map_response_code(res.status(), None)?;

    // Read response body
    let pubkey_hex_bytes = res.bytes().await?;

    // Decode key
    let mut pubkey = [0u8; KEY_SIZE];
    let bytes_decoded = HEXLOWER_PERMISSIVE
        .decode_mut(&pubkey_hex_bytes, &mut pubkey)
        .map_err(|e| {
            warn!("Could not parse public key fetched from API: {:?}", e);
            ApiError::ParseError("Invalid hex bytes for public key".to_string())
        })?;
    if bytes_decoded != KEY_SIZE {
        return Err(ApiError::ParseError(format!(
            "Invalid public key: Length must be 32 bytes, but is {} bytes",
            bytes_decoded
        )));
    }
    Ok(pubkey.into())
}

#[derive(Deserialize)]
struct IdentityPublicKey {
    identity: String,
    #[serde(rename(deserialize = "publicKey"))]
    public_key: RecipientKey,
}

/// Fetch the recipient public key for multiple Threema IDs.
pub(crate) async fn lookup_pubkeys_bulk(
    client: &Client,
    endpoint: &str,
    our_id: &str,
    their_ids: &[String],
    secret: &str,
) -> Result<HashMap<String, RecipientKey>, ApiError> {
    // Build URL
    let url = format!(
        "{}/pubkeys/bulk",
        endpoint
    );

    debug!("Looking up public key for {} Threema IDs", their_ids.len());

    // Send request
    let mut json = HashMap::new();
    json.insert("identities", their_ids.to_vec());
    let res = client.post(&url).query(&[("from", our_id),("secret", secret)]).json(&json).send().await?;
    map_response_code(res.status(), None)?;

    // Read response body
    let pub_keys: Vec<IdentityPublicKey> = res.json().await?;

    Ok(pub_keys
        .into_iter()
        .map(|k| (k.identity, k.public_key))
        .collect())
}

/// Look up an ID in the Threema directory.
pub(crate) async fn lookup_id(
    client: &Client,
    endpoint: &str,
    criterion: &LookupCriterion,
    our_id: &str,
    secret: &str,
) -> Result<String, ApiError> {
    // Build URL
    let url = match criterion {
        LookupCriterion::Phone(val) => format!("{}/lookup/phone/{}", endpoint, val),
        LookupCriterion::PhoneHash(val) => format!("{}/lookup/phone_hash/{}", endpoint, val),
        LookupCriterion::Email(val) => format!("{}/lookup/email/{}", endpoint, val),
        LookupCriterion::EmailHash(val) => format!("{}/lookup/email_hash/{}", endpoint, val),
    };

    debug!("Looking up id key for {}", criterion);

    // Send request
    let res = client.get(&url).query(&[("from", our_id),("secret", secret)]).send().await?;
    map_response_code(res.status(), Some(ApiError::BadHashLength))?;

    // Read and return response body
    Ok(res.text().await?)
}

#[derive(Serialize, Default)]
struct LookupId {
    #[serde(rename(serialize = "phoneHashes"))]
    phone_hashes: Vec<String>,
    #[serde(rename(serialize = "emailHashes"))]
    email_hashes: Vec<String>,
}


#[derive(Deserialize)]
pub struct BulkId {
    pub identity: String,
    #[serde(rename(deserialize = "publicKey"))]
    pub public_key: RecipientKey,
    #[serde(rename(deserialize = "phoneHash"))]
    pub phone_hash: Option<String>,
    #[serde(rename(deserialize = "emailHash"))]
    pub email_hash: Option<String>,
}

/// Look up an ID in the Threema directory.
pub(crate) async fn lookup_ids_bulk(
    client: &Client,
    endpoint: &str,
    criteria: &[LookupCriterion],
    our_id: &str,
    secret: &str,
) -> Result<Vec<BulkId>, ApiError> {
    let mut ids = LookupId::default();
    for criterion in criteria {
        match criterion {
            LookupCriterion::Phone(_) => ids.phone_hashes.push(criterion.hash()?),
            LookupCriterion::PhoneHash(val) => ids.phone_hashes.push(val.to_owned()),
            LookupCriterion::Email(_) => ids.email_hashes.push(criterion.hash()?),
            LookupCriterion::EmailHash(val) => ids.email_hashes.push(val.to_owned()),
        }
        if ids.phone_hashes.len() + ids.email_hashes.len() > 1000 {
            return Err(ApiError::MessageTooLong);
        }
    }
    let url = format!("{}/lookup/bulk", endpoint);

    debug!(
        "Looking up id key for {} phones and {} emails",
        ids.phone_hashes.len(),
        ids.email_hashes.len()
    );

    // Send request
    let res = client.post(&url).query(&[("from", our_id),("secret", secret)]).json(&ids).send().await?;
    map_response_code(res.status(), Some(ApiError::BadHashLength))?;

    // Read and return response body
    Ok(res.json().await?)
}

/// Look up remaining gateway credits.
pub(crate) async fn lookup_credits(
    client: &Client,
    endpoint: &str,
    our_id: &str,
    secret: &str,
) -> Result<i64, ApiError> {
    let url = format!("{}/credits", endpoint);

    debug!("Looking up remaining credits");

    // Send request
    let res = client.get(&url).query(&[("from", our_id),("secret", secret)]).send().await?;
    map_response_code(res.status(), None)?;

    // Read, parse and return response body
    let body = res.text().await?;
    body.trim().parse::<i64>().map_err(|_| {
        ApiError::ParseError(format!(
            "Could not parse response body as i64: \"{}\"",
            body
        ))
    })
}

/// Look up ID capabilities.
pub(crate) async fn lookup_capabilities(
    client: &Client,
    endpoint: &str,
    our_id: &str,
    their_id: &str,
    secret: &str,
) -> Result<Capabilities, ApiError> {
    let url = reqwest::Url::parse(endpoint)?.join("capabilities/")?.join(their_id)?;

    debug!("Looking up capabilities for {}", their_id);

    // Send request
    let res = client.get(url).query(&[("from", our_id),("secret", secret)]).send().await?;
    map_response_code(res.status(), Some(ApiError::BadHashLength))?;

    // Read response body
    let body = res.text().await?;

    // Parse response body
    body.parse()
}

#[cfg(test)]
mod tests {
    use super::{Capabilities, LookupCriterion};

    #[test]
    fn test_lookup_criterion_display() {
        let phone = LookupCriterion::Phone("1234".to_string());
        let phone_hash = LookupCriterion::PhoneHash("1234567890abcdef".to_string());
        let email = LookupCriterion::Email("user@example.com".to_string());
        let email_hash = LookupCriterion::EmailHash("1234567890abcdef".to_string());
        assert_eq!(&phone.to_string(), "phone 1234");
        assert_eq!(&phone_hash.to_string(), "phone hash 1234567890abcdef");
        assert_eq!(&email.to_string(), "email user@example.com");
        assert_eq!(&email_hash.to_string(), "email hash 1234567890abcdef");
    }

    #[test]
    fn test_parse_capabilities_empty() {
        assert_eq!(
            "".parse::<Capabilities>().unwrap(),
            Capabilities {
                text: false,
                image: false,
                video: false,
                audio: false,
                file: false,
                other: vec![],
            }
        );
    }

    #[test]
    fn test_parse_capabilities_simple() {
        assert_eq!(
            "image".parse::<Capabilities>().unwrap(),
            Capabilities {
                text: false,
                image: true,
                video: false,
                audio: false,
                file: false,
                other: vec![],
            }
        );
    }

    #[test]
    fn test_parse_capabilities_combined() {
        assert_eq!(
            "image,video,file".parse::<Capabilities>().unwrap(),
            Capabilities {
                text: false,
                image: true,
                video: true,
                audio: false,
                file: true,
                other: vec![],
            }
        );
    }

    #[test]
    fn test_parse_capabilities_unknown() {
        assert_eq!(
            "jetpack,text,lasersword".parse::<Capabilities>().unwrap(),
            Capabilities {
                text: true,
                image: false,
                video: false,
                audio: false,
                file: false,
                other: vec!["jetpack".into(), "lasersword".into()],
            }
        );
    }

    #[test]
    fn test_parse_capabilities_cleanup() {
        assert_eq!(
            "jetpack,Text ,LASERSWORD,,.,"
                .parse::<Capabilities>()
                .unwrap(),
            Capabilities {
                text: true,
                image: false,
                video: false,
                audio: false,
                file: false,
                other: vec!["jetpack".into(), "lasersword".into(), ".".into()],
            }
        );
    }

    #[test]
    fn test_parse_capabilities_can() {
        let cap = "jetpack,Text ,LASERSWORD,,.,"
            .parse::<Capabilities>()
            .unwrap();
        assert_eq!(
            cap,
            Capabilities {
                text: true,
                image: false,
                video: false,
                audio: false,
                file: false,
                other: vec!["jetpack".into(), "lasersword".into(), ".".into()],
            }
        );
        assert!(cap.can("jetpack"));
        assert!(cap.can("text"));
        assert!(cap.can("lasersword"));
        assert!(cap.can("."));
        assert!(!cap.can("image"));
    }
}
