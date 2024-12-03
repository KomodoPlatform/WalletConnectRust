use {
    relay_client::{
        error::ClientError,
        websocket::{
            connection_event_loop,
            Client,
            CloseFrame,
            ConnectionHandler,
            PublishedMessage,
        },
        ConnectionOptions,
    },
    relay_rpc::{
        auth::{ed25519_dalek::SigningKey, AuthToken},
        domain::Topic,
    },
    std::{sync::Arc, time::Duration},
    structopt::StructOpt,
    tokio::spawn,
};

#[derive(StructOpt)]
struct Args {
    /// Specify WebSocket address.
    #[structopt(short, long, default_value = "wss://relay.walletconnect.org")]
    address: String,

    /// Specify WalletConnect project ID.
    #[structopt(short, long, default_value = "86e916bcbacee7f98225dde86b697f5b")]
    project_id: String,
}

struct Handler {
    name: &'static str,
}

impl Handler {
    fn new(name: &'static str) -> Self {
        Self { name }
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
    }

    fn inbound_error(&mut self, error: ClientError) {
        println!("[{}] inbound error: {error}", self.name);
    }

    fn outbound_error(&mut self, error: ClientError) {
        println!("[{}] outbound error: {error}", self.name);
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();

    let handler = Handler::new("ws_test");
    let (client1, _) = Client::new_with_callback(handler, |rx, handler| {
        spawn(connection_event_loop(rx, handler))
    });

    client1
        .connect(&create_conn_opts(&args.address, &args.project_id))
        .await?;

    let handler = Handler::new("ws_test2");
    let (client2, _) = Client::new_with_callback(handler, |rx, handler| {
        spawn(connection_event_loop(rx, handler))
    });

    client2
        .connect(&create_conn_opts(&args.address, &args.project_id))
        .await?;

    let topic = Topic::generate();

    let subscription_id = client1.subscribe(topic.clone()).await?;
    println!("[client1] subscribed: topic={topic} subscription_id={subscription_id}");

    client2
        .publish(
            topic.clone(),
            Arc::from("Hello WalletConnect!"),
            None,
            0,
            Duration::from_secs(60),
            false,
        )
        .await?;

    println!("[client2] published message with topic: {topic}",);

    tokio::time::sleep(Duration::from_millis(500)).await;

    drop(client1);
    drop(client2);

    tokio::time::sleep(Duration::from_millis(100)).await;

    println!("clients disconnected");

    Ok(())
}
