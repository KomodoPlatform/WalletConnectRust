use {
    crate::{
        uri::{parse_wc_uri, ParseError},
        Methods,
    },
    common::{encrypt_and_encode, EnvelopeType},
    rand::{rngs::OsRng, RngCore},
    relay_client::{websocket::Client, MessageIdGenerator},
    relay_rpc::{
        domain::{MessageId, Topic},
        rpc::{
            params::{
                pairing::{PairingRequestParams, PairingResponseParamsSuccess},
                pairing_delete::PairingDeleteRequest,
                pairing_extend::PairingExtendRequest,
                pairing_ping::PairingPingRequest,
                IrnMetadata,
                Metadata,
                Relay,
                RelayProtocolMetadata,
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
    std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
    tokio::sync::Mutex,
};

/// Duration for short-term expiry (5 minutes).
const EXPIRY_5_MINS: Duration = Duration::from_secs(250); // 5 mins
/// Duration for long-term expiry (30 days).
const EXPIRY_30_DAYS: Duration = Duration::from_secs(30 * 60); // 5 mins
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone)]
pub struct Pairing {
    sym_key: String,
    version: String,
    pairing: PairingInfo,
}

/// Client for managing WalletConnect pairings.
#[derive(Debug)]
pub struct PairingClient {
    client: Arc<Client>,
    pub pairings: Arc<Mutex<HashMap<String, Pairing>>>,
}

impl PairingClient {
    pub fn new(client: Arc<Client>) -> Arc<Self> {
        Arc::new(Self {
            client,
            pairings: Arc::new(HashMap::new().into()),
        })
    }

    /// Attempts to generate a new pairing, stores it in the client's pairing
    /// list, subscribes to the pairing topic, and returns the necessary
    /// information to establish a connection.
    pub async fn try_create(
        &self,
        metadata: Metadata,
        methods: Option<Methods>,
    ) -> Result<(Topic, String), PairingClientError> {
        let now = SystemTime::now();
        let expiry = now + EXPIRY_5_MINS;
        let expiry = expiry
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

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
        // Use a block to ensure the mutex is released as soon as possible
        {
            let mut pairings = self.pairings.lock().await;
            pairings.insert(topic.clone().to_string(), pairing);
        }

        println!("\nSubscribing to topic: {topic}");

        self.client
            .subscribe(topic.clone())
            .await
            .map_err(PairingClientError::SubscriptionError)?;

        println!("\nSubscribed to topic: {topic}");

        Ok((topic, uri))
    }

    pub async fn pair(&self, url: &str) -> Result<Topic, PairingClientError> {
        println!("Attempting to pair with URI: {}", url);
        let parsed = parse_wc_uri(url).map_err(PairingClientError::ParseError)?;

        let now = SystemTime::now();
        let expiry = now + Duration::from_secs(parsed.expiry_timestamp);
        let expiry = expiry
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PairingClientError::TimeError(e.to_string()))?
            .as_secs();

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

        let pairing = Pairing {
            sym_key: parsed.sym_key,
            version: parsed.version,
            pairing: pairing_info,
        };

        let mut pairings = self.pairings.lock().await;
        if pairings.contains_key(&parsed.topic) {
            println!("Pairing with topic {} already exists", parsed.topic);
            return Err(PairingClientError::PairingTopicAlreadyExists);
        }

        pairings.insert(parsed.topic.clone(), pairing);

        println!("\nSubscribing to topic: {}", parsed.topic);

        self.client
            .subscribe(parsed.topic.clone().into())
            .await
            .map_err(PairingClientError::SubscriptionError)?;

        println!("\nSubscribed to topic: {:?}", parsed.topic);

        Ok(parsed.topic.into())
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

    /// Activates the pairing associated with the given topic,
    /// extends its expiry time, and sends a pairing extend request to the peer.
    pub async fn activate(&self, topic: &str) -> Result<(), PairingClientError> {
        let now = SystemTime::now();
        let expiry = now + EXPIRY_30_DAYS;
        let expiry = expiry
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let ping_request = PairingRequestParams::PairingExtend(PairingExtendRequest { expiry });
        self.publish_request(topic, ping_request).await?;

        // Re-acquire the lock to update the pairing
        let mut pairings = self.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.active = true;
            pairing.pairing.expiry = expiry;

            Ok(())
        } else {
            Err(PairingClientError::PairingNotFound)
        }
    }

    /// Update pairing expiry
    pub async fn update_expiry(&self, topic: &str, expiry: u64) {
        let mut pairings = self.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.expiry = expiry;
        }
    }

    /// Update pairing metadata
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
    pub async fn delete_pairing(&self, topic: &str) -> Result<(), PairingClientError> {
        println!("Attempting to unsubscribe from topic: {topic}");
        {
            self.client
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
    pub async fn ping(&self, topic: &str) -> Result<(), PairingClientError> {
        println!("Attempting to ping topic: {}", topic);
        let ping_request = PairingRequestParams::PairingPing(PairingPingRequest {});
        self.publish_request(topic, ping_request).await?;

        Ok(())
    }

    /// Used to inform the peer to close and delete a pairing.
    /// The associated authentication state of the given
    /// pairing must also be deleted.
    ///
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingdelete
    pub async fn disconnect(&self, topic: &str) -> Result<(), PairingClientError> {
        println!("Attempting to delete topic: {}", topic);
        {
            let mut pairings = self.pairings.lock().await;
            if pairings.remove(topic).is_some() {
                self.publish_request(
                    topic,
                    PairingRequestParams::PairingDelete(PairingDeleteRequest {
                        code: 6000,
                        message: "User requested disconnect".to_owned(),
                    }),
                )
                .await?;
            };
        }

        self.delete_pairing(topic).await?;

        Ok(())
    }

    /// Used to update the lifetime of a pairing.
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingextend
    pub async fn extend(&self, topic: &str, expiry: u64) -> Result<(), PairingClientError> {
        println!("Attempting to extend topic: {}", topic);

        let now = SystemTime::now();
        let expiry = now + Duration::from_secs(expiry);
        let expiry = expiry
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let extend_request = PairingRequestParams::PairingExtend(PairingExtendRequest { expiry });
        self.publish_request(topic, extend_request).await?;

        Ok(())
    }

    /// Function to publish a request
    async fn publish_request(
        &self,
        topic: &str,
        params: PairingRequestParams,
    ) -> Result<(), PairingClientError> {
        let irn_metadata = params.irn_metadata();
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, params.into());
        // Publish the encrypted message
        self.publish_payload(topic, irn_metadata, Payload::Request(request))
            .await?;

        println!("Otbound request sent!\n");

        Ok(())
    }

    /// Function to publish a request response
    pub async fn publish_response(
        &self,
        topic: &str,
        params: PairingResponseParamsSuccess,
        message_id: MessageId,
    ) -> Result<(), PairingClientError> {
        let irn_metadata = params.irn_metadata();
        let response = Response::Success(SuccessfulResponse {
            id: message_id,
            jsonrpc: JSON_RPC_VERSION_STR.into(),
            result: serde_json::to_value(params)
                .map_err(|err| PairingClientError::EncodeError(err.to_string()))?,
        });

        // Publish the encrypted message
        self.publish_payload(topic, irn_metadata, Payload::Response(response))
            .await?;

        println!("\nOutbound request sent!");

        Ok(())
    }

    async fn publish_payload(
        &self,
        topic: &str,
        irn_metadata: IrnMetadata,
        payload: Payload,
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
            self.client
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

    /// Function to generate a WalletConnect URI
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
