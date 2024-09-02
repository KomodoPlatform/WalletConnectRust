use {
    crypto::encrypt_and_encode,
    rand::{rngs::OsRng, RngCore},
    relay_client::{websocket::Client, MessageIdGenerator},
    relay_rpc::{
        domain::Topic,
        rpc::{
            params::{
                pairing::PairingRequestParams,
                pairing_ping::PairingPingRequest,
                IrnMetadata,
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
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

pub mod crypto;
pub mod pairing;

const EXPIRY_5_MINS: Duration = Duration::from_secs(250); // 5 mins
const EXPIRY_30_DAYS: Duration = Duration::from_secs(30 * 60); // 5 mins
const RELAY_PROTOCOL: &str = "irn";
const VERSION: &str = "2.0";

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

#[derive(Debug, Serialize, PartialEq, Eq, Hash, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub description: String,
    pub url: String,
    pub icons: Vec<String>,
    pub name: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Hash, Deserialize, Clone, Default)]
pub struct Relay {
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub data: Option<String>,
}

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

#[derive(Debug, Clone)]
pub struct Pairing {
    sym_key: String,
    version: String,
    pairing: PairingInfo,
}

#[derive(Debug)]
pub struct PairingClient {
    client: Arc<Client>,
    pub pairings: Arc<Mutex<HashMap<String, Pairing>>>,
}

impl PairingClient {
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            pairings: Arc::new(HashMap::new().into()),
        }
    }

    /// returns Self, Topic, Uri
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
        {
            let mut pairings = self.pairings.lock().unwrap();
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

    pub fn sym_key(&self, topic: &str) -> Result<String, PairingClientError> {
        let pairings = self.pairings.lock().unwrap();
        if let Some(key) = pairings.get(topic) {
            return Ok(key.sym_key.to_owned());
        };

        Err(PairingClientError::PairingNotFound)
    }

    pub fn get_pairing(&self, topic: &str) -> Option<Pairing> {
        let pairings = self.pairings.lock().unwrap();
        pairings.get(topic).cloned()
    }

    pub fn activate(&self, topic: &str) {
        let mut pairings = self.pairings.lock().unwrap();
        if let Some(pairing) = pairings.get_mut(topic) {
            let now = SystemTime::now();
            let expiry = now + EXPIRY_30_DAYS;
            let expiry = expiry
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            pairing.pairing.active = true;
            pairing.pairing.expiry = expiry;
        }
    }

    pub fn update_expiry(&self, topic: &str, expiry: u64) {
        let mut pairings = self.pairings.lock().unwrap();
        if let Some(pairing) = pairings.get_mut(topic) {
            pairing.pairing.expiry = expiry;
        }
    }

    pub fn update_metadata(&self, topic: &str, metadata: Metadata) {
        let mut pairings = self.pairings.lock().unwrap();
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

        let mut pairings = self.pairings.lock().unwrap();
        pairings.remove(topic);

        Ok(())
    }

    pub async fn ping(&self, topic: &str) -> Result<(), PairingClientError> {
        let pairing = {
            let pairings = self.pairings.lock().unwrap();
            pairings.get(topic).cloned()
        };

        if let Some(pairing) = pairing {
            let sym_key = hex::decode(pairing.sym_key.clone())
                .map_err(|err| PairingClientError::EncodeError(err.to_string()))?;
            let ping_request = PairingRequestParams::PairingPing(PairingPingRequest {});
            let irn_metadata = ping_request.irn_metadata();
            self.publish_request(topic, ping_request, irn_metadata, &sym_key)
                .await?;
        }

        Ok(())
    }

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
