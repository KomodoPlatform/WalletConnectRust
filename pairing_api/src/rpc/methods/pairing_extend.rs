//! https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods
//! #wc_pairingextend

use serde::{Deserialize, Serialize};
use crate::rpc::shared::IrnMetadata;

pub(crate) const IRN_REQUEST_METADATA: IrnMetadata = IrnMetadata {
    tag: 1004,
    ttl: 86400,
    prompt: false,
};

pub(crate) const IRN_RESPONSE_METADATA: IrnMetadata = IrnMetadata {
    tag: 1005,
    ttl: 86400,
    prompt: false,
};

#[derive(Debug, Serialize, PartialEq, Eq, Hash, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PairingExtendRequest {
    pub code: i64,
    pub message: String,
}
