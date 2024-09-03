use {
    crypto::encrypt_and_encode,
    rand::{rngs::OsRng, RngCore},
    relay_client::{websocket::Client, MessageIdGenerator},
    relay_rpc::{
        domain::Topic,
        rpc::{
            params::{
                pairing::PairingRequestParams,
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
            SubscriptionError,
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

pub mod crypto;
pub mod pairing;

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
    PairingTopicAlreadyExits,
    #[error("PublishError error")]
    PingError(relay_client::error::Error<PublishError>),
    #[error("Encode error")]
    EncodeError(String),
}

/// Detailed information about a pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingInfo {
    pub topic: String,
    pub relay: Relay,
    pub peer_metadata: Metadata,
    pub expiry: u64,
    pub active: bool,
    pub methods: Vec<Vec<String>>,
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
        methods: Vec<Vec<String>>,
    ) -> Result<(String, String), PairingClientError> {
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
            methods,
            expiry,
            relay,
            topic: topic.clone().to_string(),
            peer_metadata: metadata,
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

        Ok((topic.to_string(), uri))
    }

    pub fn pair(&self, _uri: &str) -> Result<(), PairingClientError> {
        todo!()
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
        let mut pairings = self.pairings.lock().await;
        let pairing = pairings
            .get_mut(topic)
            .ok_or_else(|| PairingClientError::PairingNotFound)?;

        let now = SystemTime::now();
        let expiry = now + EXPIRY_30_DAYS;
        let expiry = expiry
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // try to extend session before updating local store.
        let sym_key = hex::decode(pairing.sym_key.clone()).map_err(|err| {
            PairingClientError::EncodeError(format!("Failed to decode sym_key: {:?}", err))
        })?;
        let ping_request = PairingRequestParams::PairingExtend(PairingExtendRequest { expiry });
        let irn_metadata = ping_request.irn_metadata();

        // Release the mutex lock before the async operation
        drop(pairings);
        self.publish_request(topic, ping_request, irn_metadata, &sym_key)
            .await?;

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

    pub async fn update_expiry(&self, topic: &str, expiry: u64) {
        let mut pairings = self.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.expiry = expiry;
        }
    }

    pub async fn update_metadata(&self, topic: &str, metadata: Metadata) {
        let mut pairings = self.pairings.lock().await;
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.peer_metadata = metadata;
        }
    }

    pub async fn delete_pairing(&self, topic: &str) -> Result<(), PairingClientError> {
        {
            self.client
                .unsubscribe(topic.into())
                .await
                .map_err(PairingClientError::SubscriptionError)?;
        };

        let mut pairings = self.pairings.lock().await;
        pairings.remove(topic);

        Ok(())
    }

    /// Used to evaluate if peer is currently online. Timeout at 30 seconds
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingping
    pub async fn ping_request(&self, topic: &str) -> Result<(), PairingClientError> {
        println!("Attempting to ping topic: {}", topic);
        let pairing = {
            let pairings = self.pairings.lock().await;
            pairings.get(topic).cloned()
        };

        if let Some(pairing) = pairing {
            let sym_key = hex::decode(pairing.sym_key.clone()).map_err(|err| {
                PairingClientError::EncodeError(format!("Failed to decode sym_key: {:?}", err))
            })?;
            let ping_request = PairingRequestParams::PairingPing(PairingPingRequest {});
            let irn_metadata = ping_request.irn_metadata();
            self.publish_request(topic, ping_request, irn_metadata, &sym_key)
                .await?;

            return Ok(());
        }

        Err(PairingClientError::PairingNotFound)
    }

    /// Used to inform the peer to close and delete a pairing.
    /// The associated authentication state of the given
    /// pairing must also be deleted.
    ///
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingdelete
    pub async fn delete_request(&self, topic: &str) -> Result<(), PairingClientError> {
        println!("Attempting to delete topic: {}", topic);
        let pairing = {
            let pairings = self.pairings.lock().await;
            pairings.get(topic).cloned()
        };

        if let Some(pairing) = pairing {
            let sym_key = hex::decode(pairing.sym_key.clone()).map_err(|err| {
                PairingClientError::EncodeError(format!("Failed to decode sym_key: {:?}", err))
            })?;
            let delete_request = PairingRequestParams::PairingDelete(PairingDeleteRequest {
                code: 6000,
                message: "User requested disconnect".to_owned(),
            });
            let irn_metadata = delete_request.irn_metadata();
            self.publish_request(topic, delete_request, irn_metadata, &sym_key)
                .await?;

            return Ok(());
        }

        Err(PairingClientError::PairingNotFound)
    }

    /// Used to update the lifetime of a pairing.
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/rpc-methods#wc_pairingextend
    pub async fn extend_request(&self, topic: &str, expiry: u64) -> Result<(), PairingClientError> {
        println!("Attempting to extend topic: {}", topic);
        let pairing = {
            let pairings = self.pairings.lock().await;
            pairings.get(topic).cloned()
        };

        if let Some(pairing) = pairing {
            let sym_key = hex::decode(pairing.sym_key.clone()).map_err(|err| {
                PairingClientError::EncodeError(format!("Failed to decode sym_key: {:?}", err))
            })?;

            let now = SystemTime::now();
            let expiry = now + Duration::from_secs(expiry);
            let expiry = expiry
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            let extend_request =
                PairingRequestParams::PairingExtend(PairingExtendRequest { expiry });
            let irn_metadata = extend_request.irn_metadata();

            self.publish_request(topic, extend_request, irn_metadata, &sym_key)
                .await?;

            return Ok(());
        }

        Err(PairingClientError::PairingNotFound)
    }

    /// Function to publish a request
    async fn publish_request(
        &self,
        topic: &str,
        params: PairingRequestParams,
        irn_metadata: IrnMetadata,
        key: &[u8],
    ) -> Result<(), PairingClientError> {
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, params.into());
        let payload = serde_json::to_string(&Payload::Request(request))
            .map_err(|err| PairingClientError::EncodeError(err.to_string()))?;
        let message = encrypt_and_encode(crypto::EnvelopeType::Type0, payload, key)
            .map_err(|e| anyhow::anyhow!(e))
            .map_err(|err| PairingClientError::EncodeError(err.to_string()))?;

        println!("\nOutbound encrypted payload={message}");

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

        println!("\nOutbound payload sent!");

        Ok(())
    }

    /// Function to generate a WalletConnect URI
    fn generate_uri(pairing: &PairingInfo, sym_key: &str) -> String {
        let methods_str = pairing
            .methods
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
    let mut sym_key = [0u8; 32]; // 32 bytes = 256 bits
    OsRng.fill_bytes(&mut sym_key); // Fill the array with secure random bytes

    // Convert the sym_key to a hexadecimal string
    hex::encode(sym_key)
}
