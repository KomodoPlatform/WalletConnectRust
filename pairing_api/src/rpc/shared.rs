use serde_json::Value;

/// Relay IRN protocol metadata.
///
/// https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc
/// #definitions
#[derive(Debug, Clone, Copy)]
pub struct IrnMetadata {
    pub tag: u32,
    pub ttl: u64,
    pub prompt: bool,
}

/// Relay protocol metadata.
///
///  https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods
pub trait RelayProtocolMetadata {
    /// Retrieves IRN relay protocol metadata.
    ///
    /// Every method must return corresponding IRN metadata.
    fn irn_metadata(&self) -> IrnMetadata;
}

pub trait RelayProtocolHelpers {
    type Params;

    /// Converts "unnamed" payload parameters into typed.
    ///
    /// Example: success and error response payload does not specify the
    /// method. Thus the only way to deserialize the data into typed
    /// parameters, is to use the tag to determine the response method.
    ///
    /// This is a convenience method, so that users don't have to deal
    /// with the tags directly.
    fn irn_try_from_tag(value: Value, tag: u32) -> Result<Self::Params, ParamsError>;
}


/// Errors covering Sign API payload parameter conversion issues.
#[derive(Debug, thiserror::Error)]
pub enum ParamsError {
    /// PAiring API serialization/deserialization issues.
    #[error("Failure serializing/deserializing Sign API parameters: {0}")]
    Serde(#[from] serde_json::Error),
    /// Pairing API invalid response tag.
    #[error("Response tag={0} does not match any of the Sign API methods")]
    ResponseTag(u32),
}
