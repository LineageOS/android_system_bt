//! ACL management

use bt_hal::AclHal;
use bt_packets::hci::AclPacket;
use gddi::{module, provides, Stoppable};
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

module! {
    acl_module,
    providers {
        AclDispatch => provide_acl_dispatch,
    },
}

/// Base ACL connection trait
pub trait Connection {
    /// Get the handle of this connection
    fn get_handle(&self) -> u16;
    /// Get the sender side of inbound traffic
    fn get_tx(&self) -> &Sender<AclPacket>;
}

/// Manages rx and tx for open ACL connections
#[derive(Clone, Stoppable)]
pub struct AclDispatch {
    connections: Arc<Mutex<HashMap<u16, Box<dyn Connection + Sync + Send>>>>,
}

impl AclDispatch {
    /// Register the provided connection with the ACL dispatch
    pub async fn register(&mut self, connection: Box<dyn Connection + Sync + Send>) {
        assert!(self
            .connections
            .lock()
            .await
            .insert(connection.get_handle(), connection)
            .is_none());
    }
}

const QCOM_DEBUG_HANDLE: u16 = 0xedc;

#[provides]
async fn provide_acl_dispatch(acl: AclHal, rt: Arc<Runtime>) -> AclDispatch {
    let connections: Arc<Mutex<HashMap<u16, Box<dyn Connection + Sync + Send>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let clone_connections = connections.clone();

    rt.spawn(async move {
        select! {
            Some(acl) = consume(&acl.rx) => {
                match connections.lock().await.get(&acl.get_handle()) {
                    Some(connection) => connection.get_tx().send(acl).await.unwrap(),
                    None if acl.get_handle() == QCOM_DEBUG_HANDLE => {},
                    None => info!("no acl for {}", acl.get_handle()),
                }
            }
        }
    });

    AclDispatch { connections: clone_connections }
}

async fn consume(evt_rx: &Arc<Mutex<Receiver<AclPacket>>>) -> Option<AclPacket> {
    evt_rx.lock().await.recv().await
}
