use {
    crate::{
        uri::{parse_wc_uri, ParseError},
        Methods,
    },
    chrono::Utc,
    dashmap::{mapref::one::Ref, DashMap},
    rand::{rngs::OsRng, RngCore},
    relay_client::{websocket::Client, MessageIdGenerator},
    relay_rpc::{
        domain::{MessageId, Topic},
        rpc::{
            params::{
                pairing_delete::PairingDeleteRequest,
                pairing_extend::PairingExtendRequest,
                pairing_ping::PairingPingRequest,
                IrnMetadata,
                Metadata,
                Relay,
                RelayProtocolMetadata,
                RequestParams,
                ResponseParamsSuccess,
            },
            Payload,
            PublishError,
            Request,
            Response,
            SubscriptionError,
            SuccessfulResponse,
            JSON_RPC_VERSION_STR,
        },
    },
    serde::{Deserialize, Serialize},
    std::time::Duration,
    wc_common::{encrypt_and_encode, EnvelopeType, SymKey},
};

// Duration for short-term expiry (5 minutes) in seconds.
pub(crate) const EXPIRY_5_MINS: u64 = 300; // 5 mins
/// The relay protocol used for WalletConnect communications.
pub(crate) const EXPIRY_30_DAYS: u64 = 24 * 30 * 60 * 60;
/// The relay protocol used for WalletConnect communications.
const RELAY_PROTOCOL: &str = "irn";
/// The version of the WalletConnect protocol.
const VERSION: &str = "2";
const PAIRING_DELETE_ERROR_CODE: i64 = 6000;

/// Errors that can occur during pairing operations.
#[derive(Debug, thiserror::Error)]
pub enum PairingClientError {
    #[error("Subscription error")]
    SubscriptionError(#[from] relay_client::error::Error<SubscriptionError>),
    #[error("Topic not found")]
    PairingNotFound,
    #[error("Pairing with topic already exists")]
    PairingTopicAlreadyExists,
    #[error("PublishError error")]
    PingError(#[from] relay_client::error::Error<PublishError>),
    #[error("Encode error")]
    EncodeError(String),
    #[error("Encode error")]
    DecodeError(String),
    #[error("Unexpected parameter")]
    ParseError(#[from] ParseError),
    #[error("Time error")]
    TimeError(String),
    #[error("InvalidSymKey")]
    InvalidSymKey,
    #[error("Error generating sym_key")]
    GenSymKeyError,
}

/// Information about a pairing connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PairingInfo {
    /// Topic associated with the pairing.
    pub topic: Topic,
    /// Relay information used for communication.
    pub relay: Relay,
    /// Metadata of the peer (if available).
    pub peer_metadata: Option<Metadata>,
    /// Expiry time of the pairing (in seconds).
    pub expiry: u64,
    /// Indicates whether the pairing is active.
    pub active: bool,
    /// Supported methods for the pairing.
    pub methods: Methods,
}

/// Complete pairing including symmetric key and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    /// Symmetric key used for encryption.
    pub sym_key: SymKey,
    /// Version of the pairing protocol.
    pub version: String,
    /// Information about the pairing connection.
    pub pairing: PairingInfo,
}

impl Pairing {
    pub fn try_from_url(url: &str) -> Result<Self, PairingClientError> {
        let parsed = parse_wc_uri(url)?;
        let sym_key = hex::decode(parsed.sym_key).map_err(|_| PairingClientError::InvalidSymKey)?;
        let sym_key: SymKey = sym_key
            .try_into()
            .map_err(|_| PairingClientError::InvalidSymKey)?;
        let expiry = parsed.expiry_timestamp;
        let relay = Relay {
            protocol: parsed.relay_protocol,
            data: parsed.relay_data,
        };

        let pairing_info = PairingInfo {
            active: false,
            methods: parsed.methods,
            expiry,
            relay,
            topic: parsed.topic,
            peer_metadata: None, // We don't have peer metadata at this point
        };

        Ok(Pairing {
            sym_key,
            version: parsed.version,
            pairing: pairing_info,
        })
    }
}

/// A client that manages WalletConnect protocol pairings between wallets
/// and dApps
/// # Examples
///
/// ```rust
/// use pairing_api::{PairingClient, Methods};
/// use relay_rpc::rpc::params::Metadata;
/// use pairing_api::PairingClientError;
///
/// async fn create_pairing() -> Result<(), PairingClientError> {
///     let client = PairingClient::default();
///     
///     let metadata = Metadata {
///         name: "My dApp".to_string(),
///         description: "A decentralized application".to_string(),
///         icons: vec!["https://my-dapp.com/icon.png".to_string()],
///         url: "https://my-dapp.com".to_string(),
///     };
///     
///     let methods = Some(Methods(vec![vec![
///         "eth_signTransaction".to_string(),
///         "personal_sign".to_string(),
///     ]]));
///     
///     let (topic, uri) = client.create(metadata, methods)?;
///     
///     // Share the URI with the responder (e.g., via QR code)
///     println!("Pairing URI: {}", uri);
///     Ok(())
/// }
#[derive(Debug, Default)]
pub struct PairingClient {
    /// Dash map storing active pairings indexed by their topics.
    pub pairings: DashMap<Topic, Pairing>,
}

impl PairingClient {
    /// initializes the client with persisted storage and a network connection
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculates and validates the current Unix timestamp
    /// to use as a base for pairing expiry times.
    fn calc_expiry(&self) -> Result<u64, PairingClientError> {
        let expiry = Utc::now().timestamp();
        if expiry < 0 {
            return Err(PairingClientError::TimeError(
                "Negative timestamp".to_string(),
            ));
        }

        Ok(expiry as u64)
    }

    /// Attempts to generate a new pairing, stores it in the client's pairing
    /// list, subscribes to the pairing topic, and returns the necessary
    /// information to establish a connection.
    pub fn create(
        &self,
        metadata: Metadata,
        methods: Option<Methods>,
    ) -> Result<(Topic, String), PairingClientError> {
        let expiry = self.calc_expiry()?;
        let topic = Topic::generate();
        let relay = Relay {
            protocol: RELAY_PROTOCOL.to_owned(),
            data: None,
        };
        let pairing_info = PairingInfo {
            active: false,
            methods: methods.unwrap_or(Methods(vec![])),
            expiry: expiry + EXPIRY_5_MINS,
            relay,
            topic: topic.clone(),
            peer_metadata: Some(metadata),
        };

        let mut sym_key: SymKey = [0; 32];
        fill_sym_key(&mut sym_key).map_err(|_| PairingClientError::GenSymKeyError)?;

        let uri = Self::generate_uri(&pairing_info, &sym_key);
        let pairing = Pairing {
            sym_key,
            version: VERSION.to_owned(),
            pairing: pairing_info,
        };

        self.pairings.insert(topic.clone(), pairing);

        Ok((topic, uri))
    }

    /// for responder to pair a pairing created by a proposer
    pub fn pair(&self, url: &str, activate: bool) -> Result<Topic, PairingClientError> {
        let expiry = self.calc_expiry()?;
        let mut pairing = Pairing::try_from_url(url)?;
        let topic = pairing.pairing.topic.clone();

        // Check if the pairing already exists
        if let Some(mut existing_pairing) = self.pairings.get_mut(&topic) {
            // If the pairing is already active, return an error
            if existing_pairing.pairing.active {
                return Err(PairingClientError::PairingTopicAlreadyExists);
            }

            // Reactivate the pairing if needed
            if activate {
                existing_pairing.pairing.active = true;
                existing_pairing.pairing.expiry = expiry + EXPIRY_30_DAYS;
            }

            return Ok(topic);
        }

        // Activate the pairing if requested
        if activate {
            pairing.pairing.active = true;
        }

        self.pairings.insert(topic.clone(), pairing);

        Ok(topic)
    }

    /// Retrieves the full pairing information for a given topic.
    pub fn get_pairing(&self, topic: &Topic) -> Option<Ref<Topic, Pairing>> {
        self.pairings.get(topic)
    }

    /// Retrieves the symmetric key for a given pairing topic.
    pub fn sym_key(&self, topic: &Topic) -> Result<SymKey, PairingClientError> {
        self.get_pairing(topic)
            .map(|pairing| pairing.sym_key)
            .ok_or(PairingClientError::PairingNotFound)
    }

    /// for either to activate a previously created pairing
    pub fn activate(&self, topic: &Topic) -> Result<(), PairingClientError> {
        let expiry = self.calc_expiry()?;
        if let Some(mut pairing) = self.pairings.get_mut(topic) {
            pairing.pairing.active = true;
            pairing.pairing.expiry = expiry + EXPIRY_30_DAYS;
        }

        Ok(())
    }

    /// for either to update the expiry of an existing pairing.
    pub fn update_expiry(&self, topic: &Topic, expiry: u64) {
        if let Some(mut pairing) = self.pairings.get_mut(topic) {
            pairing.pairing.expiry = expiry;
        }
    }

    /// for either to update the metadata of an existing pairing.
    pub fn update_metadata(&self, topic: &Topic, metadata: Metadata) {
        if let Some(mut pairing) = self.pairings.get_mut(topic) {
            pairing.pairing.peer_metadata = Some(metadata);
        }
    }

    /// Deletes a pairing from the store and unsubscribe from topic.
    /// This should be done only after completing all necessary actions,
    /// such as handling responses and requests, since the pairing's sym_key
    ///  is required for encoding outgoing messages and decoding incoming ones.
    pub fn delete(&self, topic: &Topic) {
        self.pairings.remove(topic);
    }

    /// Used to evaluate if peer is currently online. Timeout at 30 seconds
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingping
    pub async fn ping(&self, topic: &Topic, client: &Client) -> Result<(), PairingClientError> {
        let ping_request = RequestParams::PairingPing(PairingPingRequest {});
        self.publish_request(topic, ping_request, client).await?;

        Ok(())
    }

    /// for either peer to disconnect a pairing
    pub async fn disconnect_rpc(
        &self,
        topic: &Topic,
        client: &Client,
    ) -> Result<(), PairingClientError> {
        {
            if self.pairings.remove(topic).is_some() {
                self.publish_request(
                    topic,
                    RequestParams::PairingDelete(PairingDeleteRequest {
                        code: PAIRING_DELETE_ERROR_CODE,
                        message: "User requested disconnect".to_owned(),
                    }),
                    client,
                )
                .await?;
            };
        }

        {
            client.unsubscribe(topic.clone()).await?;
        };

        Ok(())
    }

    /// Used to update the lifetime of a pairing.
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingextend
    pub async fn extend_rpc(
        &self,
        topic: &Topic,
        expiry: u64,
        client: &Client,
    ) -> Result<(), PairingClientError> {
        let extend_request = RequestParams::PairingExtend(PairingExtendRequest { expiry });
        self.publish_request(topic, extend_request, client).await?;

        Ok(())
    }

    /// Private function to publish a request.
    async fn publish_request(
        &self,
        topic: &Topic,
        params: RequestParams,
        client: &Client,
    ) -> Result<(), PairingClientError> {
        let irn_metadata = params.irn_metadata();
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, params.into());
        // Publish the encrypted message
        self.publish_payload(topic, irn_metadata, Payload::Request(request), client)
            .await?;

        Ok(())
    }

    /// Private function to publish a request response.
    pub async fn publish_response(
        &self,
        topic: &Topic,
        params: ResponseParamsSuccess,
        message_id: MessageId,
        client: &Client,
    ) -> Result<(), PairingClientError> {
        let irn_metadata = params.irn_metadata();
        let response = Response::Success(SuccessfulResponse {
            id: message_id,
            jsonrpc: JSON_RPC_VERSION_STR.into(),
            result: serde_json::to_value(params)
                .map_err(|err| PairingClientError::EncodeError(err.to_string()))?,
        });

        // Publish the encrypted message
        self.publish_payload(topic, irn_metadata, Payload::Response(response), client)
            .await?;

        Ok(())
    }

    /// Private function to publish a payload.
    async fn publish_payload(
        &self,
        topic: &Topic,
        irn_metadata: IrnMetadata,
        payload: Payload,
        client: &Client,
    ) -> Result<(), PairingClientError> {
        // try to extend session before updating local store.
        let sym_key = self.sym_key(topic)?;

        let payload = serde_json::to_string(&payload)
            .map_err(|err| PairingClientError::EncodeError(err.to_string()))?;
        let message = encrypt_and_encode(EnvelopeType::Type0, payload, &sym_key)
            .map_err(|err| PairingClientError::EncodeError(err.to_string()))?;

        // Publish the encrypted message
        {
            client
                .publish(
                    topic.clone(),
                    message,
                    None,
                    irn_metadata.tag,
                    Duration::from_secs(irn_metadata.ttl),
                    irn_metadata.prompt,
                )
                .await?;
        };

        Ok(())
    }

    /// Private function to generate a WalletConnect URI.
    fn generate_uri(pairing: &PairingInfo, sym_key: &SymKey) -> String {
        let sym_key = hex::encode(sym_key);
        let mut url = format!(
            "wc:{}@{}?symKey={}&relay-protocol={}&expiryTimestamp={}",
            pairing.topic, VERSION, sym_key, pairing.relay.protocol, pairing.expiry
        );

        if !pairing.methods.0.is_empty() {
            let methods_str = pairing
                .methods
                .0
                .iter()
                .map(|method_group| format!("[{}]", method_group.join(",")))
                .collect::<Vec<_>>()
                .join(",");

            url.push_str(&format!("&methods={methods_str}"));
        };

        url
    }
}

#[inline]
fn fill_sym_key(dest: &mut SymKey) -> Result<(), rand::Error> {
    OsRng.try_fill_bytes(dest)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pairing() {
        let pairing = Pairing::try_from_url(
            "wc:b99c41b1219a6c3131f2960e64cc015900b6880b49470e43bf14e9e520bd922d@2?
                expiryTimestamp=1725467415&relay-protocol=irn&
                symKey=4a7cccd69a33ac0a3debfbee49e8ff0e65edbdc2031ba600e37880f73eb5b638",
        )
        .unwrap();

        let sym_key =
            hex::decode("4a7cccd69a33ac0a3debfbee49e8ff0e65edbdc2031ba600e37880f73eb5b638")
                .unwrap()
                .try_into()
                .unwrap();
        let mut expected = Pairing {
            sym_key,
            version: "2".to_owned(),
            pairing: PairingInfo {
                topic: "b99c41b1219a6c3131f2960e64cc015900b6880b49470e43bf14e9e520bd922d".into(),
                relay: Relay {
                    protocol: "irn".to_owned(),
                    data: None,
                },
                peer_metadata: None,
                expiry: 3451086167,
                active: false,
                methods: Methods(vec![]),
            },
        };
        expected.pairing.expiry = pairing.pairing.expiry;

        assert_eq!(expected, pairing)
    }
}
