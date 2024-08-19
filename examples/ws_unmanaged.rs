use futures_util::StreamExt;
use relay_client::{websocket::{Client, Connection, ConnectionControl, PublishedMessage}, ConnectionOptions};
use relay_rpc::{auth::{ed25519_dalek::SigningKey, AuthToken}, domain::Topic};
use tokio::spawn;
use std::{sync::Arc, time::Duration};
use relay_client::websocket::StreamEvent;
use structopt::StructOpt;


#[derive(StructOpt)]
struct Args {
    /// Specify WebSocket address.
    #[structopt(short, long, default_value = "wss://relay.walletconnect.org")]
    address: String,

    /// Specify WalletConnect project ID.
    #[structopt(short, long, default_value = "86e916bcbacee7f98225dde86b697f5b")]
    project_id: String,
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

async fn client_event_loop(client: Arc<Client>){
    let mut conn = Connection::new();
    if let Some(control_rx)= client.control_rx() {
        let mut control_rx = control_rx.lock().await;

        loop {
            tokio::select! {
                event = control_rx.recv() => {
                    match event {
                        Some(event) => match event {
                            ConnectionControl::Connect { request, tx } => {
                                let result = conn.connect(request).await;
                                if result.is_ok() {
                                    println!("Client connected");
                                }
                                tx.send(result).ok();
                            }
                            ConnectionControl::Disconnect { tx } => {
                                tx.send(conn.disconnect().await).ok();
                            }
                            ConnectionControl::OutboundRequest(request) => {
                                conn.request(request);
                            }
                        }
                        // Control TX has been dropped, shutting down.
                        None => {
                            conn.disconnect().await.ok();
                            println!("Client disconnected");
                            break;
                        }
                    }
                }
                event = conn.select_next_some() => {
                    match event {
                        StreamEvent::InboundSubscriptionRequest(request) => {
                            println!("messaged: received: {:?}", PublishedMessage::from_request(&request));
                            request.respond(Ok(true)).ok();
                        }
                        StreamEvent::InboundError(error) => {
                            println!("Inbound error: {:?}", error);
                        }
                        StreamEvent::OutboundError(error) => {
                            println!("Outbound error: {:?}", error);
                        }
                        StreamEvent::ConnectionClosed(frame) => {
                            println!("connection closed: frame={frame:?}");
                            conn.reset();
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();

    let client1 = Arc::new(Client::new_unmanaged());
    spawn(client_event_loop(client1.clone()));

    client1
        .connect(&create_conn_opts(&args.address, &args.project_id))
        .await?;

    let client2 = Arc::new(Client::new_unmanaged());
    spawn(client_event_loop(client2.clone()));

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
