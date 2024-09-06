use {
    crate::EXPIRY_5_MINS,
    lazy_static::lazy_static,
    regex::Regex,
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        time::{SystemTime, UNIX_EPOCH},
    },
    thiserror::Error,
    url::Url,
};

lazy_static! {
    static ref TOPIC_VERSION_REGEX: Regex =
        Regex::new(r"^(?P<topic>[[:word:]-]+)@(?P<version>\d+)$").expect("Failed to compile regex");
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid URI")]
    InvalidUri,
    #[error("Missing topic")]
    MissingTopic,
    #[error("Invalid version")]
    InvalidVersion,
    #[error("Missing symmetric key")]
    MissingSymKey,
    #[error("Invalid symmetric key")]
    InvalidSymKey,
    #[error("Missing methods")]
    MissingMethods,
    #[error("Invalid methods format")]
    InvalidMethods,
    #[error("Missing relay protocol")]
    MissingRelayProtocol,
    #[error("Invalid expiry timestamp")]
    InvalidExpiryTimestamp,
    #[error("Unexpected parameter: {0}")]
    UnexpectedParameter(String),
}

#[derive(Debug)]
pub struct ParsedWcUri {
    pub topic: String,
    pub version: String,
    pub sym_key: String,
    pub methods: Methods,
    pub relay_protocol: String,
    pub relay_data: Option<String>,
    pub expiry_timestamp: u64,
}

pub fn parse_wc_uri(uri: &str) -> Result<ParsedWcUri, ParseError> {
    let url = Url::parse(uri).map_err(|_| ParseError::InvalidUri)?;

    if url.scheme() != "wc" {
        return Err(ParseError::InvalidUri);
    }

    let (topic, version) = {
        let caps = TOPIC_VERSION_REGEX
            .captures(url.path().trim())
            .ok_or(ParseError::InvalidUri)?;
        let topic = caps
            .name("topic")
            .ok_or(ParseError::MissingTopic)?
            .as_str()
            .to_owned();
        let version = caps
            .name("version")
            .ok_or(ParseError::InvalidVersion)?
            .as_str()
            .to_owned();

        (topic, version)
    };

    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        params.insert(key.trim().to_string(), value.trim().to_string());
    }

    let methods_str = params.remove("methods");
    let methods = parse_methods(methods_str.as_deref())?;

    let sym_key = params.remove("symKey").ok_or(ParseError::MissingSymKey)?;
    let relay_protocol = params
        .remove("relay-protocol")
        .ok_or(ParseError::MissingRelayProtocol)?;
    let relay_data = params.remove("relay-data");

    let expiry_timestamp = match params.remove("expiryTimestamp").map(|t| {
        t.parse::<u64>()
            .map_err(|_| ParseError::InvalidExpiryTimestamp)
    }) {
        None => {
            let now = SystemTime::now();
            let expiry = now + EXPIRY_5_MINS;
            expiry
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
        }

        Some(time) => time?,
    };

    // Check for unexpected parameters
    if !params.is_empty() {
        return Err(ParseError::UnexpectedParameter(
            params.keys().next().unwrap().clone(),
        ));
    }

    Ok(ParsedWcUri {
        topic,
        version,
        sym_key,
        methods,
        relay_protocol,
        relay_data,
        expiry_timestamp,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Methods(pub Vec<Vec<String>>);

fn parse_methods(methods_str: Option<&str>) -> Result<Methods, ParseError> {
    if methods_str.is_none() {
        return Ok(Methods(vec![]));
    }

    let trimmed = methods_str.unwrap().trim_matches('[').trim_matches(']');
    if trimmed.is_empty() {
        return Ok(Methods(vec![]));
    }

    let method_groups: Vec<Vec<String>> = trimmed
        .split("],[")
        .map(|group| {
            group
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    Ok(Methods(method_groups))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_methods() {
        // Test the provided example
        let input = "[wc_sessionPropose],[wc_authRequest,wc_authBatchRequest]";
        let expected = Methods(vec![vec!["wc_sessionPropose".to_string()], vec![
            "wc_authRequest".to_string(),
            "wc_authBatchRequest".to_string(),
        ]]);
        assert_eq!(parse_methods(Some(input)).unwrap(), expected);

        // Test single method
        let input = "[wc_sessionPropose]";
        let expected = Methods(vec![vec!["wc_sessionPropose".to_string()]]);
        assert_eq!(parse_methods(Some(input)).unwrap(), expected);

        // Test multiple groups
        let input = "[method1,method2],[method3],[method4,method5]";
        let expected = Methods(vec![
            vec!["method1".to_string(), "method2".to_string()],
            vec!["method3".to_string()],
            vec!["method4".to_string(), "method5".to_string()],
        ]);
        assert_eq!(parse_methods(Some(input)).unwrap(), expected);

        // Test empty input
        let input = "[]";
        assert!(parse_methods(Some(input)).is_ok());

        // Test empty group
        let input = "[method1],[]";
        assert!(parse_methods(Some(input)).is_ok());
    }
}
