//! A client that connects to HciLayerFacadeService

// TODO(qasimj): This client is temporary and is used for testing only.
// It will be removed later.

use grpcio::*;

use std::sync::Arc;

use futures::TryStreamExt;

use bt_hci as hci;
use hci::facade::protos::empty::Empty;
use hci::facade::protos::facade::{CommandMsg, EventCodeMsg};
use hci::facade::protos::hci_layer_facade_grpc::HciLayerFacadeClient;

fn new_event_code(code: u32) -> EventCodeMsg {
    let mut event_code = EventCodeMsg::default();
    event_code.set_code(code);
    event_code
}

fn new_command(bytes: Vec<u8>) -> CommandMsg {
    let mut cmd = CommandMsg::default();
    cmd.set_command(bytes);
    cmd
}

async fn register_event_handler(
    client: &HciLayerFacadeClient,
    event_code: &EventCodeMsg,
) -> Result<()> {
    let register_event_handler = client.register_event_handler_async(event_code)?;
    register_event_handler.await?;

    Ok(())
}

async fn enqueue_command_with_complete(
    client: &HciLayerFacadeClient,
    cmd: &CommandMsg,
) -> Result<()> {
    let enqueue = client.enqueue_command_with_complete_async(cmd)?;
    enqueue.await?;
    Ok(())
}

async fn fetch_events(client: &HciLayerFacadeClient) -> Result<()> {
    let mut fetch_events = client.fetch_events(&Empty::new())?;
    while let Some(event) = fetch_events.try_next().await? {
        println!("Received Event: {:?}", event);
    }
    Ok(())
}

async fn async_main() -> Result<()> {
    let env = Arc::new(Environment::new(2));
    let channel = ChannelBuilder::new(env).connect("pop-os:8999");
    let client = HciLayerFacadeClient::new(channel);

    println!("Registering event handler!");
    register_event_handler(&client, &new_event_code(0x0eu32)).await?;

    let handle = fetch_events(&client);
    let cmd = &new_command(vec![0x0du8, 0x08, 0x04, 0x07, 0x00, 0x06, 0x00]);

    println!("Enqueue commands");
    enqueue_command_with_complete(&client, cmd).await.unwrap();

    enqueue_command_with_complete(&client, cmd).await.unwrap();

    println!("Waiting for events...");
    handle.await.unwrap();

    Ok(())
}

fn main() {
    futures::executor::block_on(async_main()).unwrap();
}
