use {
    pairing_api::PairingClient,
    relay_client::{
        error::ClientError,
        websocket::{Client, CloseFrame, ConnectionHandler, PublishedMessage},
        ConnectionOptions,
    },
    relay_rpc::{
        auth::{ed25519_dalek::SigningKey, AuthToken},
        domain::Topic,
        rpc::{params::ResponseParamsSuccess, Params, Payload},
    },
    std::{sync::Arc, time::Duration},
    structopt::StructOpt,
    tokio::{
        signal,
        spawn,
        sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    },
    wc_common::decode_and_decrypt_type0,
};

#[derive(StructOpt)]
struct Args {
    /// Specify WebSocket address.
    #[structopt(short, long, default_value = "wss://relay.walletconnect.com")]
    address: String,

    /// Specify WalletConnect project ID.
    #[structopt(short, long, default_value = "1979a8326eb123238e633655924f0a78")]
    project_id: String,
}

struct Handler {
    name: &'static str,
    sender: UnboundedSender<PublishedMessage>,
}

fn create_conn_opts(address: &str, project_id: &str) -> ConnectionOptions {
    let key = SigningKey::generate(&mut rand::thread_rng());

    let auth = AuthToken::new("http://127.0.0.1:8000")
        .aud(address)
        .ttl(Duration::from_secs(60 * 60))
        .as_jwt(&key)
        .unwrap();

    ConnectionOptions::new(project_id, auth).with_address(address)
}

impl Handler {
    fn new(name: &'static str, sender: UnboundedSender<PublishedMessage>) -> Self {
        Self { name, sender }
    }
}

impl ConnectionHandler for Handler {
    fn connected(&mut self) {
        println!("[{}] connection open", self.name);
    }

    fn disconnected(&mut self, frame: Option<CloseFrame<'static>>) {
        println!("[{}] connection closed: frame={frame:?}", self.name);
    }

    fn message_received(&mut self, message: PublishedMessage) {
        println!(
            "[{}] inbound message: topic={} message={}",
            self.name, message.topic, message.message
        );

        if let Err(err) = self.sender.send(message.clone()) {
            println!("error {err:?} while sending {message:?}");
        };
    }

    fn inbound_error(&mut self, error: ClientError) {
        println!("[{}] inbound error: {error}", self.name);
    }

    fn outbound_error(&mut self, error: ClientError) {
        println!("[{}] outbound error: {error}", self.name);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();
    let (sender, receiver) = unbounded_channel();
    let client1 = Arc::new(Client::new(Handler::new("client1", sender)));
    client1
        .connect(&create_conn_opts(&args.address, &args.project_id))
        .await?;

    let pairing_client = Arc::new(PairingClient::new());
    // Create Pairing.
    // let topic = create_pairing(&pairing_client).await;
    // Pair
    let topic = pair_from_uri(&pairing_client, &client1).await;
    // Subscribe to the pairing topic
    println!("\nSubscribing to topic: {}", topic);
    client1
        .subscribe(topic.clone().into())
        .await
        .map_err(PairingClientError::SubscriptionError)?;
    println!("\nSuccessfully subscribed to topic: {:?}", topic);

    let pairing = pairing_client.get_pairing(topic.as_ref()).await.unwrap();
    let key = pairing_client.sym_key(topic.as_ref()).await.unwrap();
    let receiver_handle = spawn(spawn_published_message_recv_loop(
        client1,
        pairing_client,
        receiver,
        key,
    ));

    // Keep the main task running
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("Received Ctrl+C, shutting down");
        }
        _ = receiver_handle => {
            println!("Receiver loop ended");
        }
    };

    Ok(())
}

async fn spawn_published_message_recv_loop(
    client: Arc<Client>,
    pairing_client: Arc<PairingClient>,
    mut recv: UnboundedReceiver<PublishedMessage>,
    key: String,
) {
    while let Some(msg) = recv.recv().await {
        let topic = msg.topic.to_string();
        let key = hex::decode(key.clone()).unwrap();
        let message = decode_and_decrypt_type0(msg.message.as_bytes(), &key).unwrap();
        println!("\nInbound message payload={message}");

        let response = serde_json::from_str::<Payload>(&message).unwrap();
        match response {
            Payload::Request(request) => match request.params {
                Params::PairingDelete(_) => {
                    // send a success response back to wc.
                    let delete_request = ResponseParamsSuccess::PairingDelete(true);
                    pairing_client
                        .publish_response(&topic, delete_request, request.id, &client)
                        .await
                        .unwrap();
                    // send a request to delete pairing from store.
                    pairing_client.delete(&topic, &client).await.unwrap();
                }
                Params::PairingExtend(data) => {
                    let extend_request = ResponseParamsSuccess::PairingExtend(true);
                    // send a success response back to wc.
                    pairing_client
                        .publish_response(&topic, extend_request, request.id, &client)
                        .await
                        .unwrap();
                    // send a request to update pairing expiry in store.
                    pairing_client.update_expiry(&topic, data.expiry).await;
                }
                Params::PairingPing(_) => {
                    let ping_request = ResponseParamsSuccess::PairingPing(true);
                    // send a success response back to wc.
                    pairing_client
                        .publish_response(&topic, ping_request, request.id, &client)
                        .await
                        .unwrap();
                }
                _ => unimplemented!(),
            },
            Payload::Response(value) => {
                println!("Response: {value:?}");
            }
        }
    }
}

async fn pair_from_uri(pairing_client: &PairingClient, client: &Client) -> Topic {
    pairing_client
        .pair(
            "wc:
    b99c41b1219a6c3131f2960e64cc015900b6880b49470e43bf14e9e520bd922d@2?
    expiryTimestamp=1725467415&relay-protocol=irn&
    symKey=4a7cccd69a33ac0a3debfbee49e8ff0e65edbdc2031ba600e37880f73eb5b638",
            true,
            client,
        )
        .await
        .unwrap()
}

// async fn create_pairing(pairing_client: &PairingClient) -> Topic {
//     let metadata = Metadata {
//         description: "A decentralized application that enables secure
//         communication and transactions."
//             .to_string(),
//         url: "https://127.0.0.1:3000".to_string(),
//         icons: vec![
//             "https://example-dapp.com/icon1.png".to_string(),
//             "https://example-dapp.com/icon2.png".to_string(),
//         ],
//         name: "Example DApp".to_string(),
//     };

//     let (topic, uri) = pairing_client.try_create(metadata,
// None).await.unwrap();     println!("pairing_uri: {uri}");

//     topic
// }
//
