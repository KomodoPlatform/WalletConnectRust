use {
    super::{
        pairing_delete::PairingDeleteRequest,
        pairing_extend::PairingExtendRequest,
        pairing_ping::PairingPingRequest,
    },
    crate::rpc::{
        params::{IrnMetadata, ParamsError, RelayProtocolHelpers, RelayProtocolMetadata},
        ErrorData,
        Params,
    },
    paste::paste,
    serde::{Deserialize, Serialize},
    serde_json::Value,
};

// Convenience macro to de-duplicate implementation for different parameter
// sets.
#[macro_export]
macro_rules! impl_relay_protocol_metadata {
    ($param_type:ty,$meta:ident) => {
        paste! {
            impl RelayProtocolMetadata for $param_type {
                fn irn_metadata(&self) -> IrnMetadata {
                    match self {
                        [<$param_type>]::PairingDelete(_) => $crate::rpc::params::pairing_delete::[<IRN_ $meta:upper _METADATA>],
                        [<$param_type>]::PairingExtend(_) => $crate::rpc::params::pairing_extend::[<IRN_ $meta:upper _METADATA>],
                        [<$param_type>]::PairingPing(_) => $crate::rpc::params::pairing_ping::[<IRN_ $meta:upper _METADATA>],
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
            impl RelayProtocolHelpers for $param_type {
                type Params = Self;

                fn irn_try_from_tag(value: Value, tag: u32) -> Result<Self::Params, ParamsError> {
                    match tag {
                        tag if tag == $crate::rpc::params::pairing_delete::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::PairingDelete(serde_json::from_value(value)?))
                        }
                        tag if tag == $crate::rpc::params::pairing_extend::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::PairingExtend(serde_json::from_value(value)?))
                        }
                        tag if tag == $crate::rpc::params::pairing_ping::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::PairingPing(serde_json::from_value(value)?))
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
pub enum PairingResponseParamsError {
    PairingDelete(ErrorData),
    PairingExtend(ErrorData),
    PairingPing(ErrorData),
}

impl_relay_protocol_metadata!(PairingResponseParamsError, response);
impl_relay_protocol_helpers!(PairingResponseParamsError);

/// Typed success response parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PairingResponseParamsSuccess {
    PairingExtend(bool),
    PairingDelete(bool),
    PairingPing(bool),
}
impl_relay_protocol_metadata!(PairingResponseParamsSuccess, response);
impl_relay_protocol_helpers!(PairingResponseParamsSuccess);

/// Pairing API request parameters.
///
/// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods
/// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/data-structures
pub enum PairingRequestParams {
    PairingExtend(PairingExtendRequest),
    PairingDelete(PairingDeleteRequest),
    PairingPing(PairingPingRequest),
}
impl_relay_protocol_metadata!(PairingRequestParams, request);

impl From<PairingRequestParams> for Params {
    fn from(value: PairingRequestParams) -> Self {
        match value {
            PairingRequestParams::PairingDelete(param) => Params::PairingDelete(param),
            PairingRequestParams::PairingPing(param) => Params::PairingPing(param),
            PairingRequestParams::PairingExtend(param) => Params::PairingExtend(param),
        }
    }
}
