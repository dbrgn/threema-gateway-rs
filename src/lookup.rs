//! ID and public key lookups.

use std::{fmt, str};

use crypto_box::KEY_SIZE;
use data_encoding::HEXLOWER_PERMISSIVE;
use reqwest::Client;

use crate::{
    connection::map_response_code, errors::ApiError, RecipientKey, SDK_HEADER, SDK_USER_AGENT,
};

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

impl fmt::Display for LookupCriterion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LookupCriterion::Phone(ref n) => write!(f, "phone {}", n),
            LookupCriterion::PhoneHash(ref nh) => write!(f, "phone hash {}", nh),
            LookupCriterion::Email(ref e) => write!(f, "email {}", e),
            LookupCriterion::EmailHash(ref eh) => write!(f, "email hash {}", eh),
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
    // Build URL
    let url = format!(
        "{}/pubkeys/{}?from={}&secret={}",
        endpoint, their_id, our_id, secret
    );

    debug!("Looking up public key for {}", their_id);

    // Send request
    let res = client
        .get(&url)
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
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

/// Look up an ID in the Threema directory.
pub(crate) async fn lookup_id(
    client: &Client,
    endpoint: &str,
    criterion: &LookupCriterion,
    our_id: &str,
    secret: &str,
) -> Result<String, ApiError> {
    // Build URL
    let url_base = match criterion {
        LookupCriterion::Phone(ref val) => format!("{}/lookup/phone/{}", endpoint, val),
        LookupCriterion::PhoneHash(ref val) => format!("{}/lookup/phone_hash/{}", endpoint, val),
        LookupCriterion::Email(ref val) => format!("{}/lookup/email/{}", endpoint, val),
        LookupCriterion::EmailHash(ref val) => format!("{}/lookup/email_hash/{}", endpoint, val),
    };
    let url = format!("{}?from={}&secret={}", url_base, our_id, secret);

    debug!("Looking up id key for {}", criterion);

    // Send request
    let res = client
        .get(&url)
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
    map_response_code(res.status(), Some(ApiError::BadHashLength))?;

    // Read and return response body
    Ok(res.text().await?)
}

/// Look up remaining gateway credits.
pub(crate) async fn lookup_credits(
    client: &Client,
    endpoint: &str,
    our_id: &str,
    secret: &str,
) -> Result<i64, ApiError> {
    let url = format!("{}/credits?from={}&secret={}", endpoint, our_id, secret);

    debug!("Looking up remaining credits");

    // Send request
    let res = client
        .get(&url)
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
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
    // Build URL
    let url = format!(
        "{}/capabilities/{}?from={}&secret={}",
        endpoint, their_id, our_id, secret
    );

    debug!("Looking up capabilities for {}", their_id);

    // Send request
    let res = client
        .get(&url)
        .header(SDK_HEADER, SDK_USER_AGENT)
        .send()
        .await?;
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
