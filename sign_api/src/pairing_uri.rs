// topic = "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9"
// version = 2
// symKey = "587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303"
// methods = [wc_sessionPropose],[wc_authRequest,wc_authBatchRequest]
// relay = { protocol: "irn", data: "" }
// Required

// symKey (STRING) = symmetric key used for pairing encryption
// methods (STRING) = comma separated array of inner arrays of methods. Inner
// arrays are grouped by ProtocolType relay-protocol (STRING) = protocol name
// used for relay Optional

// relay-data (STRING) = hex data payload used for relay
// expiryTimestamp (UINT) = unixr timestamp in seconds - after the timestamp the
// pairing is considered expired, should be generated 5 minutes in the future

use {
    lazy_static::lazy_static,
    regex::Regex,
    std::{collections::HashMap, str::FromStr},
    thiserror::Error,
    url::Url,
};

lazy_static! {
    static ref TOPIC_VERSION_REGEX: Regex =
        Regex::new(r"^(?P<topic>[[:word:]-]+)@(?P<version>\d+)$").expect("Failed to compile regex");
}

#[derive(PartialEq, Eq)]
pub struct PairingParams {
    pub sym_key: Vec<u8>,
    pub relay_protocol: String,
    pub relay_data: Option<String>,
    pub expiry_timestamp: Option<u64>,
}

#[derive(PartialEq, Eq)]
pub struct Pairing {
    pub topic: String,
    pub version: String,
    pub params: PairingParams,
}

impl std::fmt::Debug for Pairing {
    /// Debug with key masked.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WCPairingUrl")
            .field("topic", &self.topic)
            .field("version", &self.version)
            .field("relay-protocol", &self.params.relay_protocol)
            .field("key", &"***")
            .field(
                "relay-data",
                &self.params.relay_data.as_deref().unwrap_or(""),
            )
            .finish()
    }
}

impl FromStr for Pairing {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::from_str(s).map_err(|err| ParseError::InvalidData(err.to_string()))?;
        if url.scheme() != "wc" {
            return Result::Err(ParseError::UnexpectedProtocol(url.scheme().to_owned()));
        }

        let (topic, version) = Self::try_topic_and_version_from_path(url.path())?;
        let params = Self::try_params_from_url(&url)?;

        Ok(Self {
            topic,
            version,
            params,
        })
    }
}

impl Pairing {
    fn try_topic_and_version_from_path(path: &str) -> Result<(String, String), ParseError> {
        let caps = TOPIC_VERSION_REGEX
            .captures(path)
            .ok_or(ParseError::InvalidTopicAndVersion)?;

        let topic = caps
            .name("topic")
            .ok_or(ParseError::TopicNotFound)?
            .as_str()
            .to_owned();

        let version = caps
            .name("version")
            .ok_or(ParseError::VersionNotFound)?
            .as_str()
            .to_owned();

        Ok((topic, version))
    }

    /// Try to parse WalletConnect pairing url
    fn try_params_from_url(url: &Url) -> Result<PairingParams, ParseError> {
        let mut params = HashMap::new();
        let queries = url.query_pairs();

        for (key, value) in queries {
            let sanitized_key: String = key
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '-')
                .collect();
            if let Some(existing) = params.insert(sanitized_key.to_string(), value.to_string()) {
                return Err(ParseError::UnexpectedParameter(key.into_owned(), existing));
            }
        }

        let relay_protocol = params
            .remove("relay-protocol")
            .ok_or(ParseError::RelayProtocolNotFound)?;

        let sym_key = params
            .remove("symKey")
            .ok_or(ParseError::KeyNotFound)
            .and_then(|key| hex::decode(key).map_err(ParseError::InvalidSymKey))?;

        let relay_data = params.remove("relay-data");
        let expiry_timestamp = params
            .remove("expiryTimestamp")
            .and_then(|t| t.parse::<u64>().ok());

        if !params.is_empty() {
            let (key, value) = params.iter().next().unwrap();
            return Err(ParseError::UnexpectedParameter(key.clone(), value.clone()));
        }

        Ok(PairingParams {
            relay_protocol,
            sym_key,
            relay_data,
            expiry_timestamp,
        })
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid topic and version format")]
    InvalidTopicAndVersion,
    #[error("Topic not found")]
    TopicNotFound,
    #[error("Version not found")]
    VersionNotFound,
    #[error("Relay protocol not found")]
    RelayProtocolNotFound,
    #[error("Symmetric key not found")]
    KeyNotFound,
    #[error("Invalid symmetric key: {0}")]
    InvalidSymKey(#[from] hex::FromHexError),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Unexpected parameter: {0} = {1}")]
    UnexpectedParameter(String, String),
    #[error("Unexpected protocol: {0}")]
    UnexpectedProtocol(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uri() {
        let uri = "wc:c9e6d30fb34afe70a15c14e9337ba8e4d5a35dd695c39b94884b0ee60c69d168@2?\
                   relay-protocol=irn&\
                   symKey=7ff3e362f825ab868e20e767fe580d0311181632707e7c878cbeca0238d45b8b";

        let actual = Pairing {
            topic: "c9e6d30fb34afe70a15c14e9337ba8e4d5a35dd695c39b94884b0ee60c69d168".to_owned(),
            version: "2".to_owned(),
            params: PairingParams {
                relay_protocol: "irn".to_owned(),
                sym_key: hex::decode(
                    "7ff3e362f825ab868e20e767fe580d0311181632707e7c878cbeca0238d45b8b",
                )
                .unwrap()
                .into(),
                relay_data: None,
                expiry_timestamp: None,
            },
        };
        let expected = Pairing::from_str(uri).unwrap();

        assert_eq!(actual, expected);
    }
}
