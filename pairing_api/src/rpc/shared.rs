use {
    crate::rpc::params,
    paste::paste,
    relay_rpc::rpc::ErrorData,
    serde::{Deserialize, Serialize},
    serde_json::Value,
};

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
    /// Pairing API serialization/deserialization issues.
    #[error("Failure serializing/deserializing Sign API parameters: {0}")]
    Serde(#[from] serde_json::Error),
    /// Pairing API invalid response tag.
    #[error("Response tag={0} does not match any of the Sign API methods")]
    ResponseTag(u32),
}

// Convenience macro to de-duplicate implementation for different parameter
// sets.
#[macro_export]
macro_rules! impl_relay_protocol_metadata {
    ($param_type:ty,$meta:ident) => {
        paste! {
            impl $crate::rpc::shared::RelayProtocolMetadata for $param_type {
                fn irn_metadata(&self) -> $crate::rpc::shared::IrnMetadata {
                    match self {
                        [<$param_type>]::Delete(_) => params::pairing_delete::[<IRN_ $meta:upper _METADATA>],
                        [<$param_type>]::Extend(_) => params::pairing_extend::[<IRN_ $meta:upper _METADATA>],
                        [<$param_type>]::Ping(_) => params::pairing_ping::[<IRN_ $meta:upper _METADATA>],
                    }
                }
            }
        }
    }
}

// Convenience macro to de-duplicate implementation for different parameter
// sets.
#[macro_export]
macro_rules! impl_relay_protocol_helpers {
    ($param_type:ty) => {
        paste! {
            impl $crate::rpc::shared::RelayProtocolHelpers for $param_type {
                type Params = Self;

                fn irn_try_from_tag(value: Value, tag: u32) -> Result<Self::Params, ParamsError> {
                    match tag {
                        tag if tag == params::pairing_delete::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::Delete(serde_json::from_value(value)?))
                        }
                        tag if tag == params::pairing_extend::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::Extend(serde_json::from_value(value)?))
                        }
                        tag if tag == params::pairing_ping::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::Ping(serde_json::from_value(value)?))
                        }
                        _ => Err(ParamsError::ResponseTag(tag)),
                    }
                }
            }
        }
    };
}

/// Typed error response parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseParamsError {
    Delete(ErrorData),
    Extend(ErrorData),
    Ping(ErrorData),
}

impl_relay_protocol_metadata!(ResponseParamsError, response);
impl_relay_protocol_helpers!(ResponseParamsError);
