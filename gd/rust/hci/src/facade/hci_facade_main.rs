//! A server providing the HciLayerFacadeService

use bt_hal as hal;
use bt_hci as hci;
use futures::channel::oneshot;
use futures::executor::block_on;
use grpcio::*;
use hal::rootcanal_hal::{RootcanalConfig, RootcanalHal};
use hci::facade::hci_facade_server::HciLayerFacadeService;
use hci::Hci;

use std::io::{self, Read};
use std::sync::Arc;
use std::thread;

use tokio::runtime::Runtime;

async fn async_main(rt: Arc<Runtime>) -> Result<()> {
    let env = Arc::new(Environment::new(2));
    let hal_exports = RootcanalHal::start(RootcanalConfig::new(6402, "127.0.0.1"), Arc::clone(&rt)).await.unwrap();
    let hci_exports = Hci::start(hal_exports, Arc::clone(&rt));
    let mut server = ServerBuilder::new(env)
        .register_service(HciLayerFacadeService::create(hci_exports, Arc::clone(&rt)))
        .bind("0.0.0.0", 8999)
        .build()
        .unwrap();
    server.start();

    let (tx, rx) = oneshot::channel();

    thread::spawn(move || {
        println!("Press ENTER to exit...");
        let _ = io::stdin().read(&mut [0]).unwrap();
        tx.send(())
    });
    block_on(rx).unwrap();
    block_on(server.shutdown()).unwrap();

    Ok(())
}

fn main() {
    let rt = Arc::new(Runtime::new().unwrap());
    let runtime = Arc::clone(&rt);
    runtime.block_on(async_main(rt)).unwrap();
}
