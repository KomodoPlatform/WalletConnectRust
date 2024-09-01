use {
    rand::{rngs::OsRng, RngCore},
    relay_client::websocket::Client,
    relay_rpc::{domain::Topic, rpc::SubscriptionError},
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

pub mod crypto;
pub mod pairing;
pub mod rpc;

const EXPIRY: Duration = Duration::from_secs(250); // 5 mins
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
    pub expiry: Option<u64>,
    pub active: bool,
    pub methods: Vec<Vec<String>>,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Pairing {
    sym_key: String,
    pairing: PairingInfo,
}

#[derive(Debug)]
pub struct PairingClient {
    client: Arc<Client>,
    pub pairings: Arc<Mutex<HashMap<String, Arc<Pairing>>>>,
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
        let expiry = now + EXPIRY;
        let expiry = Some(
            expiry
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
        );

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
            version: VERSION.to_owned(),
        };
        let uri = Self::generate_uri(&pairing_info, &sym_key);

        let pairing = Arc::new(Pairing {
            sym_key: sym_key.clone(),
            pairing: pairing_info,
        });
        let mut pairings = self.pairings.lock().unwrap();
        pairings.insert(topic.clone().to_string(), pairing);

        println!("\nSubscribing to topic: {topic}");
        self.client
            .subscribe(topic.clone())
            .await
            .map_err(PairingClientError::SubscriptionError)?;
        println!("\nSubscribed to topic: {topic}");

        Ok((topic.to_string(), uri))
    }

    pub fn pair(&self, uri: &str) -> Result<(), PairingClientError> {

        Ok(())
    }

    pub fn sym_key(&self, topic: &str) -> Result<String, PairingClientError> {
        let pairings = self.pairings.lock().unwrap();
        if let Some(key) = pairings.get(topic) {
            return Ok(key.sym_key.to_owned());
        };

        Err(PairingClientError::PairingNotFound)
    }

    pub fn get_pairing(&self, topic: &str) -> Option<Arc<Pairing>> {
        let pairings = self.pairings.lock().unwrap();
        pairings.get(topic).map(|p| p.clone())
    }

    fn generate_uri(pairing: &PairingInfo, sym_key: &str) -> String {
        let methods_str = pairing
            .methods
            .iter()
            .map(|method_group| format!("[{}]", method_group.join(",")))
            .collect::<Vec<_>>()
            .join(",");
        let expiry_timestamp_str = match pairing.expiry {
            Some(ts) => ts.to_string(),
            None => "".to_string(),
        };

        format!(
            "wc:{}@{}?symKey={}&methods={}&relay-protocol={}&expiryTimestamp={}",
            pairing.topic,
            pairing.version,
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
