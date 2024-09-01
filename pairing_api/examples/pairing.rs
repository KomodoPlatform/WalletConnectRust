use {
    pairing_api::{crypto::decode_and_decrypt_type0, Metadata, PairingClient},
    relay_client::{
        error::ClientError,
        websocket::{Client, CloseFrame, ConnectionHandler, PublishedMessage},
        ConnectionOptions,
    },
    relay_rpc::auth::{ed25519_dalek::SigningKey, AuthToken},
    std::{sync::Arc, time::Duration},
    structopt::StructOpt,
    tokio::{
        signal, spawn, sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender}, time::sleep
    },
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

fn prepare_pairing_client_data() -> (Vec<Vec<String>>, Metadata) {
    let methods = vec![vec!["wc_sessionPropose".to_string()], vec![
        "wc_authRequestDP".to_string(),
        "wc_authBatchRequest".to_string(),
    ]];
    let metadata = Metadata {
        description: "A decentralized application that enables secure communication and \
                      transactions."
            .to_string(),
        url: "https://127.0.0.1:3000".to_string(),
        icons: vec![
            "https://example-dapp.com/icon1.png".to_string(),
            "https://example-dapp.com/icon2.png".to_string(),
        ],
        name: "Example DApp".to_string(),
    };

    (methods, metadata)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();
    let (sender, receiver) = unbounded_channel();
    let client1 = Arc::new(Client::new(Handler::new("client1", sender)));
    client1
        .connect(&create_conn_opts(&args.address, &args.project_id))
        .await?;

    let pairing_client = PairingClient::new(client1);

    let (methods, metadata) = prepare_pairing_client_data();
    let (topic, uri) = pairing_client.try_create(metadata, methods).await.unwrap();
    println!("{uri:?}");

    let key = pairing_client.sym_key(&topic).unwrap();
    let receiver_handle = spawn(spawn_published_message_recv_loop(receiver, key));

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
    mut recv: UnboundedReceiver<PublishedMessage>,
    key: String,
) {
    while let Some(msg) = recv.recv().await {
        let key = hex::decode(key.clone()).unwrap();
        let message = decode_and_decrypt_type0(msg.message.as_bytes(), &key).unwrap();
        println!("decoded message=({message})");
    }
}
