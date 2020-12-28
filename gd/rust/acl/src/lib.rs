//! ACL management

mod fragment;

use bt_hal::AclHal;
use bt_packets::hci::AclPacket;
use bytes::Bytes;
use gddi::{module, provides, Stoppable};
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::Mutex;

use fragment::Reassembler;

module! {
    acl_module,
    providers {
        AclDispatch => provide_acl_dispatch,
    },
}

struct Connection {
    reassembler: Reassembler,
}

/// Manages rx and tx for open ACL connections
#[derive(Clone, Stoppable)]
pub struct AclDispatch {
    connections: Arc<Mutex<HashMap<u16, Connection>>>,
}

impl AclDispatch {
    /// Register the provided connection with the ACL dispatch
    pub async fn register(&mut self, handle: u16) -> Receiver<Bytes> {
        let (tx, rx) = channel(10);
        assert!(self
            .connections
            .lock()
            .await
            .insert(handle, Connection { reassembler: Reassembler::new(tx) })
            .is_none());

        rx
    }
}

const QCOM_DEBUG_HANDLE: u16 = 0xedc;

#[provides]
async fn provide_acl_dispatch(acl: AclHal, rt: Arc<Runtime>) -> AclDispatch {
    let connections: Arc<Mutex<HashMap<u16, Connection>>> = Arc::new(Mutex::new(HashMap::new()));
    let clone_connections = connections.clone();

    rt.spawn(async move {
        select! {
            Some(acl) = consume(&acl.rx) => {
                match connections.lock().await.get_mut(&acl.get_handle()) {
                    Some(connection) => connection.reassembler.on_packet(acl).await,
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
