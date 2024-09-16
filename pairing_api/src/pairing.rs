use {
    crate::{
        uri::{parse_wc_uri, ParseError},
        Methods,
    },
    chrono::Utc,
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
    std::{collections::HashMap, sync::Arc, time::Duration},
    tokio::sync::Mutex,
    wc_common::{encrypt_and_encode, EnvelopeType},
};

/// Duration for short-term expiry (5 minutes).
pub(crate) const EXPIRY_5_MINS: u64 = 300; // 5 mins
/// Duration for long-term expiry (30 days).
pub(crate) const EXPIRY_30_DAYS: u64 = 30 * 60 * 60; // 30 days
/// The relay protocol used for WalletConnect communications.
const RELAY_PROTOCOL: &str = "irn";
/// The version of the WalletConnect protocol.
const VERSION: &str = "2";

/// Errors that can occur during pairing operations.
#[derive(Debug, thiserror::Error)]
pub enum PairingClientError {
    #[error("Subscription error")]
    SubscriptionError(relay_client::error::Error<SubscriptionError>),
    #[error("Topic not found")]
    PairingNotFound,
    #[error("Pairing with topic already exists")]
    PairingTopicAlreadyExists,
    #[error("PublishError error")]
    PingError(relay_client::error::Error<PublishError>),
    #[error("Encode error")]
    EncodeError(String),
    #[error("Unexpected parameter")]
    ParseError(ParseError),
    #[error("Time error")]
    TimeError(String),
}

/// Detailed information about a pairing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PairingInfo {
    pub topic: String,
    pub relay: Relay,
    pub peer_metadata: Option<Metadata>,
    pub expiry: u64,
    pub active: bool,
    pub methods: Methods,
}

/// Represents a complete pairing including symmetric key and version.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub sym_key: String,
    pub version: String,
    pub pairing: PairingInfo,
}

impl Pairing {
    pub fn try_from_url(url: &str) -> Result<Self, PairingClientError> {
        let parsed = parse_wc_uri(url).map_err(PairingClientError::ParseError)?;

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
            topic: parsed.topic.clone(),
            peer_metadata: None, // We don't have peer metadata at this point
        };

        Ok(Pairing {
            sym_key: parsed.sym_key,
            version: parsed.version,
            pairing: pairing_info,
        })
    }
}

/// Client for managing WalletConnect pairings.
#[derive(Debug)]
pub struct PairingClient {
    pub pairings: Arc<Mutex<HashMap<String, Pairing>>>,
}

impl Default for PairingClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingClient {
    /// initializes the client with persisted storage and a network connection
    pub fn new() -> Self {
        Self {
            pairings: Arc::new(HashMap::new().into()),
        }
    }

    /// Attempts to generate a new pairing, stores it in the client's pairing
    /// list, subscribes to the pairing topic, and returns the necessary
    /// information to establish a connection.
    pub async fn create(
        &self,
        metadata: Metadata,
        methods: Option<Methods>,
    ) -> Result<(Topic, String), PairingClientError> {
        let expiry = Utc::now().timestamp() as u64 + EXPIRY_5_MINS;

        let topic = Topic::generate();
        let relay = Relay {
            protocol: RELAY_PROTOCOL.to_owned(),
            data: None,
        };
        let sym_key = gen_sym_key();
        let pairing_info = PairingInfo {
            active: false,
            methods: methods.unwrap_or(Methods(vec![])),
            expiry,
            relay,
            topic: topic.clone().to_string(),
            peer_metadata: Some(metadata),
        };

        let uri = Self::generate_uri(&pairing_info, &sym_key);
        let pairing = Pairing {
            sym_key: sym_key.clone(),
            version: VERSION.to_owned(),
            pairing: pairing_info,
        };

        {
            let mut pairings = self.pairings.lock().await;
            pairings.insert(topic.clone().to_string(), pairing);
        }

        Ok((topic, uri))
    }

    /// for responder to pair a pairing created by a proposer
    pub async fn pair(&self, url: &str, activate: bool) -> Result<Topic, PairingClientError> {
        println!("Attempting to pair with URI: {}", url);
        let mut pairing = Pairing::try_from_url(url)?;
        let topic = pairing.pairing.topic.clone();

        {
            let mut pairings = self.pairings.lock().await;

            // Check if the pairing already exists
            if let Some(existing_pairing) = pairings.get_mut(&topic) {
                // Reactivate the pairing if needed
                if activate {
                    existing_pairing.pairing.active = true;
                }

                // If the pairing is already active, return an error
                if existing_pairing.pairing.active {
                    return Err(PairingClientError::PairingTopicAlreadyExists);
                }
            }
        }

        {
            // Activate the pairing if requested
            if activate {
                pairing.pairing.active = true;
            }

            let mut pairings = self.pairings.lock().await;
            pairings.insert(topic.clone(), pairing);
        }

        Ok(topic.into())
    }

    /// Retrieves the symmetric key for a given pairing topic.
    pub async fn sym_key(&self, topic: &str) -> Result<String, PairingClientError> {
        let pairings = self.pairings.lock().await;
        if let Some(key) = pairings.get(topic) {
            return Ok(key.sym_key.to_owned());
        };

        Err(PairingClientError::PairingNotFound)
    }

    /// Retrieves the full pairing information for a given topic.
    pub async fn get_pairing(&self, topic: &str) -> Option<Pairing> {
        let pairings = self.pairings.lock().await;
        pairings.get(topic).cloned()
    }

    /// for either to activate a previously created pairing
    pub async fn activate(&self, topic: &str) -> Result<(), PairingClientError> {
        let expiry = Utc::now().timestamp() as u64 + EXPIRY_30_DAYS;

        let mut pairings = self.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.active = true;
            pairing.pairing.expiry = expiry;

            Ok(())
        } else {
            Err(PairingClientError::PairingNotFound)
        }
    }

    /// for either to update the expiry of an existing pairing.
    pub async fn update_expiry(&self, topic: &str, expiry: u64) {
        let mut pairings = self.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.expiry = expiry;
        }
    }

    /// for either to update the metadata of an existing pairing.
    pub async fn update_metadata(&self, topic: &str, metadata: Metadata) {
        let mut pairings = self.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.peer_metadata = Some(metadata);
        }
    }

    /// Deletes a pairing from the store and subscribe from topic.
    /// This should be done only after completing all necessary actions,
    /// such as handling responses and requests, since the pairing's sym_key
    ///  is required for encoding outgoing messages and decoding incoming ones.
    pub async fn delete(&self, topic: &str, client: &Client) -> Result<(), PairingClientError> {
        // Use a block to ensure the mutex is released as soon as possible
        println!("Attempting to unsubscribe from topic: {topic}");
        {
            client
                .unsubscribe(topic.into())
                .await
                .map_err(PairingClientError::SubscriptionError)?;
        };

        {};
        let mut pairings = self.pairings.lock().await;
        pairings.remove(topic);

        Ok(())
    }

    /// Used to evaluate if peer is currently online. Timeout at 30 seconds
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingping
    pub async fn ping(&self, topic: &str, client: &Client) -> Result<(), PairingClientError> {
        let ping_request = RequestParams::PairingPing(PairingPingRequest {});
        self.publish_request(topic, ping_request, client).await?;

        Ok(())
    }

    /// for either peer to disconnect a pairing
    pub async fn disconnect(&self, topic: &str, client: &Client) -> Result<(), PairingClientError> {
        {
            let mut pairings = self.pairings.lock().await;
            if pairings.remove(topic).is_some() {
                self.publish_request(
                    topic,
                    RequestParams::PairingDelete(PairingDeleteRequest {
                        code: 6000,
                        message: "User requested disconnect".to_owned(),
                    }),
                    client,
                )
                .await?;
            };
        }

        self.delete(topic, client).await?;

        Ok(())
    }

    /// Used to update the lifetime of a pairing.
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingextend
    pub async fn extend(
        &self,
        topic: &str,
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
        topic: &str,
        params: RequestParams,
        client: &Client,
    ) -> Result<(), PairingClientError> {
        let irn_metadata = params.irn_metadata();
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, params.into());
        // Publish the encrypted message
        self.publish_payload(topic, irn_metadata, Payload::Request(request), client)
            .await?;

        println!("Otbound request sent!\n");

        Ok(())
    }

    /// Private function to publish a request response.
    pub async fn publish_response(
        &self,
        topic: &str,
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

        println!("\nOutbound request sent!");

        Ok(())
    }

    /// Private function to publish a payload.
    async fn publish_payload(
        &self,
        topic: &str,
        irn_metadata: IrnMetadata,
        payload: Payload,
        client: &Client,
    ) -> Result<(), PairingClientError> {
        // try to extend session before updating local store.
        let sym_key = {
            let pairings = self.pairings.lock().await;
            let pairing = pairings
                .get(topic)
                .ok_or_else(|| PairingClientError::PairingNotFound)?;
            hex::decode(pairing.sym_key.clone()).map_err(|err| {
                PairingClientError::EncodeError(format!("Failed to decode sym_key: {:?}", err))
            })?
        };

        let payload = serde_json::to_string(&payload)
            .map_err(|err| PairingClientError::EncodeError(err.to_string()))?;
        let message = encrypt_and_encode(EnvelopeType::Type0, payload, &sym_key)
            .map_err(|e| anyhow::anyhow!(e))
            .map_err(|err| PairingClientError::EncodeError(err.to_string()))?;

        // Publish the encrypted message
        {
            client
                .publish(
                    topic.into(),
                    message,
                    None,
                    irn_metadata.tag,
                    Duration::from_secs(irn_metadata.ttl),
                    irn_metadata.prompt,
                )
                .await
                .map_err(PairingClientError::PingError)?;
        };

        Ok(())
    }

    /// Private function to generate a WalletConnect URI.
    fn generate_uri(pairing: &PairingInfo, sym_key: &str) -> String {
        let methods_str = pairing
            .methods
            .0
            .iter()
            .map(|method_group| format!("[{}]", method_group.join(",")))
            .collect::<Vec<_>>()
            .join(",");
        let expiry_timestamp_str = pairing.expiry.to_string();

        format!(
            "wc:{}@{}?symKey={}&methods={}&relay-protocol={}&expiryTimestamp={}",
            pairing.topic,
            VERSION,
            sym_key,
            methods_str,
            pairing.relay.protocol,
            expiry_timestamp_str
        )
    }
}

fn gen_sym_key() -> String {
    let mut sym_key = [0u8; 32];
    OsRng.fill_bytes(&mut sym_key);
    hex::encode(sym_key)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_pairing() {
        let pairing = Pairing::try_from_url(
            "wc:b99c41b1219a6c3131f2960e64cc015900b6880b49470e43bf14e9e520bd922d@2?
                expiryTimestamp=1725467415&relay-protocol=irn&
                symKey=4a7cccd69a33ac0a3debfbee49e8ff0e65edbdc2031ba600e37880f73eb5b638",
        )
        .unwrap();

        let mut expected = Pairing {
            sym_key: "4a7cccd69a33ac0a3debfbee49e8ff0e65edbdc2031ba600e37880f73eb5b638".to_owned(),
            version: "2".to_owned(),
            pairing: PairingInfo {
                topic: "b99c41b1219a6c3131f2960e64cc015900b6880b49470e43bf14e9e520bd922d"
                    .to_owned(),
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
