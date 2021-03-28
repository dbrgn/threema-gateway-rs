//! Code related to incoming messages received from Threema Gateway.

/// An incoming message received from Threema Gateway.
///
/// To receive the message, you'll need to provide your own HTTP callback
/// server implementation. The request body bytes that are received this way
/// can then be parsed using [`IncomingMessage::from_urlencoded_bytes`].
///
/// See <https://gateway.threema.ch/de/developer/api> for details.
#[serde(rename_all = "camelCase")]
#[derive(Debug, serde::Deserialize)]
pub struct IncomingMessage {
    /// Sender identity (8 characters)
    pub from: String,
    /// Your API identity (8 characters, usually starts with '*')
    pub to: String,
    /// Message ID assigned by the sender (8 bytes, hex encoded)
    pub message_id: String,
    /// Message date set by the sender (UNIX timestamp)
    pub date: usize,
    /// Nonce used for encryption (24 bytes, hex encoded)
    pub nonce: String,
    /// Encrypted message data (max. 4000 bytes, hex encoded)
    #[serde(rename = "box")]
    pub box_data: String,
    /// Message Authentication Code (32 bytes, hex encoded, see below)
    pub mac: String,
    /// Public nickname of the sender, if set
    pub nickname: Option<String>,
}

impl IncomingMessage {
    /// Deserialize an incoming Threema Gateway message in
    /// `application/x-www-form-urlencoded` format.
    pub fn from_urlencoded_bytes(
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self, serde_urlencoded::de::Error> {
        let msg: IncomingMessage = serde_urlencoded::from_bytes(bytes.as_ref())?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let msg = IncomingMessage::from_urlencoded_bytes(b"from=ECHOECHO&to=*TESTTST&messageId=0102030405060708&date=1616950936&nonce=001122334455667700112233445566770011223344556677&box=012345abcdef&mac=0011223344556677001122334455667700112233445566770011223344556677").unwrap();
        assert_eq!(msg.from, "ECHOECHO");
        assert_eq!(msg.to, "*TESTTST");
        assert_eq!(msg.box_data, "012345abcdef");
        assert_eq!(msg.nickname, None);
    }
}
