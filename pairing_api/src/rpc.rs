mod params;
#[macro_use]
mod shared;

use {
    params::{
        pairing_delete::PairingDeleteRequest,
        pairing_extend::PairingExtendRequest,
        pairing_ping::PairingPingRequest,
    },
    paste::paste,
    serde::{Deserialize, Serialize},
};

/// Pairing API request parameters.
///
/// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods
/// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/data-structures
#[derive(Debug, Serialize, Eq, Deserialize, Clone, PartialEq)]
#[serde(tag = "method", content = "params")]
pub enum PairingRequestParams {
    #[serde(rename = "wc_pairingExtend")]
    Extend(PairingExtendRequest),
    #[serde(rename = "wc_pairingDelete")]
    Delete(PairingDeleteRequest),
    #[serde(rename = "wc_pairingPing")]
    Ping(PairingPingRequest),
}

impl_relay_protocol_metadata!(PairingRequestParams, request);
