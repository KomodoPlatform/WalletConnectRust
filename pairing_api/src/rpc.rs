mod methods;
mod shared;

use {
    methods::{
        pairing_delete::PairingDeleteRequest,
        pairing_extend::PairingExtendRequest,
        pairing_ping::PairingPingRequest,
    },
    paste::paste,
    serde::{Deserialize, Serialize},
    shared::{IrnMetadata, RelayProtocolHelpers, RelayProtocolMetadata},
};

// Convenience macro to de-duplicate implementation for different parameter
// sets.
macro_rules! impl_relay_protocol_metadata {
    ($param_type:ty,$meta:ident) => {
        paste! {
            impl RelayProtocolMetadata for $param_type {
                fn irn_metadata(&self) -> IrnMetadata {
                    match self {
                        [<$param_type>]::PairingDelete(_) => methods::pairing_delete::[<IRN_ $meta:upper _METADATA>],
                        [<$param_type>]::PairingExtend(_) => methods::pairing_extend::[<IRN_ $meta:upper _METADATA>],
                        [<$param_type>]::PairingPing(_) => methods::pairing_ping::[<IRN_ $meta:upper _METADATA>],
                    }
                }
            }
        }
    }
}

macro_rules! impl_relay_protocol_helpers {
    ($param_type:ty) => {
        paste! {
            impl RelayProtocolHelpers for $param_type {
                type Params = Self;

                fn irn_try_from_tag(value: Value, tag: u32) -> Result<Self::Params, ParamsError> {
                    match tag {
                        tag if tag == methods::pairing_delete::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::PairingDelete(serde_json::from_value(value)?))
                        }
                        tag if tag == methods::pairing_extend::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::PairingExtend(serde_json::from_value(value)?))
                        }
                        tag if tag == methods::pairing_ping::IRN_RESPONSE_METADATA.tag => {
                            Ok(Self::PairingPing(serde_json::from_value(value)?))
                        }
                        _ => Err(ParamsError::ResponseTag(tag)),
                    }
                }
            }
        }
    };
}

/// Pairing API request parameters.
///
/// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods
/// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/data-structures
#[derive(Debug, Serialize, Eq, Deserialize, Clone, PartialEq)]
#[serde(tag = "method", content = "params")]
pub enum PairingRequestParams {
    #[serde(rename = "wc_pairingExtend")]
    PairingExtend(PairingExtendRequest),
    #[serde(rename = "wc_pairingDelete")]
    PairingDelete(PairingDeleteRequest),
    #[serde(rename = "wc_pairingPing")]
    PairingPing(PairingPingRequest),
}

impl_relay_protocol_metadata!(PairingRequestParams, request);
