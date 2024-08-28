use {
    anyhow::Result,
    chrono::Utc,
    clap::Parser,
    relay_client::{
        error::ClientError,
        websocket::{Client, CloseFrame, ConnectionHandler, PublishedMessage},
        ConnectionOptions,
        MessageIdGenerator,
    },
    relay_rpc::{
        auth::{ed25519_dalek::SigningKey, AuthToken},
        domain::{MessageId, SubscriptionId, Topic},
        rpc::{
            params::{
                session::{
                    delete::SessionDeleteRequest,
                    propose::{SessionProposeRequest, SessionProposeResponse},
                    settle::{Controller, SessionSettleRequest},
                    IrnMetadata,
                    ProposeNamespace,
                    ProposeNamespaces,
                    RelayProtocolMetadata,
                    RequestParams,
                    ResponseParamsSuccess,
                    SettleNamespace,
                    SettleNamespaces,
                },
                Metadata,
                Relay,
            },
            Params,
            Payload,
            Request,
            Response,
            SuccessfulResponse,
            JSON_RPC_VERSION_STR,
        },
    },
    sign_api::{
        decode_and_decrypt_type0,
        encrypt_and_encode,
        EnvelopeType,
        Pairing as PairingData,
        SessionKey,
    },
    std::{
        collections::{BTreeMap, HashMap},
        str::FromStr,
        sync::Arc,
        time::Duration,
    },
    tokio::{
        select,
        sync::{
            mpsc::{channel, unbounded_channel, Sender, UnboundedSender},
            Mutex,
        },
    },
};

const SUPPORTED_PROTOCOL: &str = "irn";
const SUPPORTED_METHODS: &[&str] = &[
    "eth_sendTransaction",
    "eth_signTransaction",
    "eth_sign",
    "personal_sign",
    "eth_signTypedData",
];
const SUPPORTED_CHAINS: &[&str] = &["eip155:1", "eip155:5"];
const SUPPORTED_EVENTS: &[&str] = &["chainChanged", "accountsChanged"];
const SUPPORTED_ACCOUNTS: &[&str] = &["eip155:5:0xBA5BA3955463ADcc7aa3E33bbdfb8A68e0933dD8"];

// Establish Session.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arg {
    /// Goerli https://react-app.walletconnect.com/ pairing URI.
    pairing_uri: String,

    /// Specify WebSocket address.
    #[arg(short, long, default_value = "wss://relay.walletconnect.com")]
    address: String,

    /// Specify WalletConnect project ID.
    #[arg(short, long, default_value = "86e916bcbacee7f98225dde86b697f5b")]
    project_id: String,
}

struct Handler {
    name: &'static str,
    sender: UnboundedSender<PublishedMessage>,
}

impl Handler {
    fn new(name: &'static str, sender: UnboundedSender<PublishedMessage>) -> Self {
        Self { name, sender }
    }
}

impl ConnectionHandler for Handler {
    fn connected(&mut self) {
        println!("\n[{}] connection open", self.name);
    }

    fn disconnected(&mut self, frame: Option<CloseFrame<'static>>) {
        println!("\n[{}] connection closed: frame={frame:?}", self.name);
    }

    fn message_received(&mut self, message: PublishedMessage) {
        println!(
            "\n[{}] inbound message: message_id={} topic={} tag={} message={}",
            self.name, message.message_id, message.topic, message.tag, message.message,
        );

        if let Err(e) = self.sender.send(message) {
            println!("\n[{}] failed to send the to the receiver: {e}", self.name);
        }
    }

    fn inbound_error(&mut self, error: ClientError) {
        println!("\n[{}] inbound error: {error}", self.name);
    }

    fn outbound_error(&mut self, error: ClientError) {
        println!("\n[{}] outbound error: {error}", self.name);
    }
}

fn create_conn_opts(address: &str, project_id: &str) -> ConnectionOptions {
    let key = SigningKey::generate(&mut rand::thread_rng());

    let auth = AuthToken::new("http://example.com")
        .aud(address)
        .ttl(Duration::from_secs(60 * 60))
        .as_jwt(&key)
        .unwrap();

    ConnectionOptions::new(project_id, auth).with_address(address)
}

fn supported_propose_namespaces() -> ProposeNamespaces {
    ProposeNamespaces({
        let mut map = BTreeMap::<String, ProposeNamespace>::new();
        map.insert("eip155".to_string(), ProposeNamespace {
            chains: SUPPORTED_CHAINS.iter().map(|c| c.to_string()).collect(),
            methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
            events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
            ..Default::default()
        });
        map
    })
}

fn supported_settle_namespaces() -> SettleNamespaces {
    SettleNamespaces({
        let mut map = BTreeMap::<String, SettleNamespace>::new();
        map.insert("eip155".to_string(), SettleNamespace {
            accounts: SUPPORTED_ACCOUNTS.iter().map(|a| a.to_string()).collect(),
            methods: SUPPORTED_METHODS.iter().map(|m| m.to_string()).collect(),
            events: SUPPORTED_EVENTS.iter().map(|e| e.to_string()).collect(),
            ..Default::default()
        });
        map
    })
}

fn create_settle_request(responder_public_key: String) -> RequestParams {
    RequestParams::SessionSettle(SessionSettleRequest {
        relay: Relay {
            protocol: SUPPORTED_PROTOCOL.to_string(),
            data: None,
        },
        controller: Controller {
            public_key: responder_public_key.to_string(),
            metadata: Metadata {
                name: format!("Rust session example: {}", Utc::now()),
                icons: vec!["https://www.rust-lang.org/static/images/rust-logo-blk.svg".to_string()],
                ..Default::default()
            },
        },
        namespaces: supported_settle_namespaces(),
        expiry: Utc::now().timestamp() as u64 + 300, // 5 min TTL
    })
}

fn create_proposal_response(responder_public_key: String) -> ResponseParamsSuccess {
    ResponseParamsSuccess::SessionPropose(SessionProposeResponse {
        relay: Relay {
            protocol: SUPPORTED_PROTOCOL.to_string(),
            data: None,
        },
        responder_public_key,
    })
}

/// https://specs.walletconnect.com/2.0/specs/clients/sign/session-proposal
async fn process_proposal_request(
    context: Arc<Mutex<Context>>,
    proposal: SessionProposeRequest,
) -> Result<ResponseParamsSuccess> {
    supported_propose_namespaces().supported(&proposal.required_namespaces)?;

    let sender_public_key = hex::decode(&proposal.proposer.public_key)?
        .as_slice()
        .try_into()?;

    let session_key = SessionKey::from_osrng(&sender_public_key)?;
    let responder_public_key = hex::encode(session_key.diffie_public_key());
    let session_topic: Topic = session_key.generate_topic().try_into()?;

    {
        let mut context = context.lock().await;
        let subscription_id = context.client.subscribe(session_topic.clone()).await?;
        _ = context.sessions.insert(session_topic.clone(), Session {
            session_key,
            subscription_id,
        });

        let settle_params = create_settle_request(responder_public_key.clone());
        context
            .publish_request(session_topic, settle_params)
            .await?;
    }
    Ok(create_proposal_response(responder_public_key))
}

fn process_session_delete_request(delete_params: SessionDeleteRequest) -> ResponseParamsSuccess {
    println!(
        "\nSession is being terminated reason={}, code={}",
        delete_params.message, delete_params.code,
    );

    ResponseParamsSuccess::SessionDelete(true)
}

async fn process_inbound_request(
    context: Arc<Mutex<Context>>,
    request: Request,
    topic: Topic,
) -> Result<()> {
    let mut session_delete_cleanup_required: Option<Topic> = None;
    let response = match request.params {
        Params::SessionPropose(proposal) => {
            process_proposal_request(context.clone(), proposal).await?
        }
        Params::SessionRequest(request) => {
            println!("params: {}", request.request.params);
            println!("method: {}", request.request.method);

            todo!()
        }
        Params::SessionDelete(params) => {
            session_delete_cleanup_required = Some(topic.clone());
            process_session_delete_request(params)
        }
        Params::SessionPing(_) => ResponseParamsSuccess::SessionPing(true),
        _ => todo!(),
    };

    let mut context = context.lock().await;
    context
        .publish_success_response(topic, request.id, response)
        .await?;

    // Corner case after the session was closed by the dapp.
    if let Some(topic) = session_delete_cleanup_required {
        context.session_delete_cleanup(topic).await?
    }

    Ok(())
}

fn process_inbound_response(response: Response) -> Result<()> {
    match response {
        Response::Success(value) => {
            let params = serde_json::from_value::<ResponseParamsSuccess>(value.result)?;
            match params {
                ResponseParamsSuccess::SessionSettle(b) => {
                    if !b {
                        anyhow::bail!("Unsuccessful response={params:?}");
                    }

                    Ok(())
                }
                _ => todo!(),
            }
        }
        Response::Error(value) => {
            // let params = serde_json::from_value::<ResponseParamsError>(value.error)?;
            anyhow::bail!("DApp send and error response: {value:?}");
        }
    }
}

async fn process_inbound_message(
    context: Arc<Mutex<Context>>,
    message: PublishedMessage,
) -> Result<()> {
    let plain = {
        let context = context.lock().await;
        context.peek_sym_key(&message.topic, |key| {
            decode_and_decrypt_type0(message.message.as_bytes(), key)
                .map_err(|e| anyhow::anyhow!(e))
        })?
    };

    println!("\nPlain payload={plain}");
    let payload: Payload = serde_json::from_str(&plain)?;

    match payload {
        Payload::Request(request) => process_inbound_request(context, request, message.topic).await,
        Payload::Response(response) => process_inbound_response(response),
    }
}

async fn inbound_handler(context: Arc<Mutex<Context>>, message: PublishedMessage) {
    if !Payload::irn_tag_in_range(message.tag) {
        println!(
            "\ntag={} skip handling, doesn't belong to Sign API",
            message.tag
        );
        return;
    }

    match process_inbound_message(context, message).await {
        Ok(_) => println!("\nMessage was successfully handled"),
        Err(e) => println!("\nFailed to handle the message={e}"),
    }
}

/// https://specs.walletconnect.com/2.0/specs/clients/core/pairing
#[allow(dead_code)]
struct Pairing {
    /// Termination signal for when all sessions have been closed.
    terminator: Sender<()>,
    /// Pairing topic.
    topic: Topic,
    /// Pairing subscription id.
    subscription_id: SubscriptionId,
    /// Pairing symmetric key.
    ///
    /// https://specs.walletconnect.com/2.0/specs/clients/core/crypto/
    /// crypto-keys#key-algorithms
    sym_key: [u8; 32],
}

/// https://specs.walletconnect.com/2.0/specs/clients/sign/session-proposal
///
/// New session as the result of successful session proposal.
#[allow(dead_code)]
struct Session {
    /// Pairing subscription id.
    subscription_id: SubscriptionId,
    /// Session symmetric key.
    ///
    /// https://specs.walletconnect.com/2.0/specs/clients/core/crypto/
    /// crypto-keys#key-algorithms
    session_key: SessionKey,
}

/// WCv2 client context.
struct Context {
    /// Relay WS client to send and receive messages.
    ///
    /// TODO: assumed re-entrant/thread-safe?
    client: Client,
    pairing: Pairing,
    /// All session belonging to `pairing`.
    ///
    /// Uniquely identified by the topic.
    sessions: HashMap<Topic, Session>,
}

impl Context {
    fn new(client: Client, pairing: Pairing) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            client,
            pairing,
            sessions: HashMap::new(),
        }))
    }

    /// Provides read access to the symmetric encryption/decryption key.
    ///
    /// Read lock is held for the duration of the call.
    fn peek_sym_key<F, T>(&self, topic: &Topic, f: F) -> Result<T>
    where
        F: FnOnce(&[u8; 32]) -> Result<T>,
    {
        if &self.pairing.topic == topic {
            f(&self.pairing.sym_key)
        } else {
            let session = self
                .sessions
                .get(topic)
                .ok_or_else(|| anyhow::anyhow!("Missing sym key for topic={} ", topic))?;

            f(&session.session_key.symmetric_key())
        }
    }

    async fn publish_request(&self, topic: Topic, params: RequestParams) -> Result<()> {
        let irn_helpers = params.irn_metadata();
        let message_id = MessageIdGenerator::new().next();
        let request = Request::new(message_id, params.into());
        let payload = serde_json::to_string(&Payload::from(request))?;
        println!("\nSending request topic={topic} payload={payload}");
        self.publish_payload(topic, irn_helpers, &payload).await
    }

    async fn publish_success_response(
        &self,
        topic: Topic,
        id: MessageId,
        params: ResponseParamsSuccess,
    ) -> Result<()> {
        let irn_metadata = params.irn_metadata();
        let response = Response::Success(SuccessfulResponse {
            id,
            jsonrpc: JSON_RPC_VERSION_STR.into(),
            result: serde_json::to_value(params).unwrap(),
        });
        let payload = serde_json::to_string(&Payload::from(response))?;
        println!("\nSending response topic={topic} payload={payload}");
        self.publish_payload(topic, irn_metadata, &payload).await
    }

    async fn publish_payload(
        &self,
        topic: Topic,
        irn_metadata: IrnMetadata,
        payload: &str,
    ) -> Result<()> {
        let encrypted = self.peek_sym_key(&topic, |key| {
            encrypt_and_encode(EnvelopeType::Type0, &payload, key).map_err(|e| anyhow::anyhow!(e))
        })?;

        println!("\nOutbound encrypted payload={encrypted}");

        self.client
            .publish(
                topic,
                Arc::from(encrypted),
                None,
                irn_metadata.tag,
                Duration::from_secs(irn_metadata.ttl),
                irn_metadata.prompt,
            )
            .await?;

        Ok(())
    }

    /// Deletes session identified by the `topic`.
    ///
    /// When session count reaches zero, unsubscribes from topic and sends
    /// termination signal to end the application execution.
    ///
    /// TODO: should really delete pairing as well:
    /// https://specs.walletconnect.com/2.0/specs/clients/core/pairing/
    /// rpc-methods#wc_pairingdelete
    async fn session_delete_cleanup(&mut self, topic: Topic) -> Result<()> {
        let _session = self
            .sessions
            .remove(&topic)
            .ok_or_else(|| anyhow::anyhow!("Attempt to remove non-existing session"))?;

        self.client.unsubscribe(topic).await?;

        // Un-pair when there are no more session subscriptions.
        // TODO: Delete pairing, not just unsubscribe.
        if self.sessions.is_empty() {
            println!("\nNo active sessions left, terminating the pairing");

            self.client.unsubscribe(self.pairing.topic.clone()).await?;

            self.pairing.terminator.send(()).await?;
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Arg::parse();
    let pairing = PairingData::from_str(&args.pairing_uri)?;
    let topic: Topic = pairing.topic.try_into()?;
    let (inbound_sender, mut inbound_receiver) = unbounded_channel();
    let (terminate_sender, mut terminate_receiver) = channel::<()>(1);

    let client = Client::new(Handler::new("example_wallet", inbound_sender));
    client
        .connect(&create_conn_opts(&args.address, &args.project_id))
        .await?;

    let subscription_id = client.subscribe(topic.clone()).await?;
    println!("\n[client1] subscribed: topic={topic} subscription_id={subscription_id}");

    let context = Context::new(client, Pairing {
        terminator: terminate_sender,
        topic,
        sym_key: pairing.params.sym_key.as_slice().try_into()?,
        subscription_id,
    });

    // Processes inbound messages until termination signal is received.
    loop {
        let context = context.clone();
        select! {
            message = inbound_receiver.recv() => {
                match message {
                    Some(m) => {
                        tokio::spawn(async move { inbound_handler(context, m).await });
                    },
                    None => {
                        break;
                    }
                }

            }
            _ = terminate_receiver.recv() => {
                terminate_receiver.close();
                inbound_receiver.close();
            }
        };
    }

    Ok(())
}
