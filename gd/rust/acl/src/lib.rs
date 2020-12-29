//! ACL management

mod fragment;

use bt_common::Bluetooth;
use bt_hal::AclHal;
use bt_hci::ControllerExports;
use bt_packets::hci::AclPacket;
use bytes::Bytes;
use fragment::{fragmenting_stream, Reassembler};
use futures::stream::{SelectAll, StreamExt};
use gddi::{module, provides, Stoppable};
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{oneshot, Mutex};

module! {
    acl_module,
    providers {
        AclDispatch => provide_acl_dispatch,
    },
}

/// A basic ACL connection
#[derive(Debug)]
pub struct Connection {
    rx: Receiver<Bytes>,
    tx: Sender<Bytes>,
}

/// Manages rx and tx for open ACL connections
#[derive(Clone, Stoppable)]
pub struct AclDispatch {
    requests: Sender<RegistrationRequest>,
}

impl AclDispatch {
    /// Register the provided connection with the ACL dispatch
    pub async fn register(&mut self, handle: u16, bt: Bluetooth) -> Connection {
        let (tx, rx) = oneshot::channel();
        self.requests.send(RegistrationRequest { handle, bt, fut: tx }).await.unwrap();
        rx.await.unwrap()
    }
}

#[derive(Debug)]
struct RegistrationRequest {
    handle: u16,
    bt: Bluetooth,
    fut: oneshot::Sender<Connection>,
}

const QCOM_DEBUG_HANDLE: u16 = 0xedc;

#[provides]
async fn provide_acl_dispatch(
    acl: AclHal,
    controller: Arc<ControllerExports>,
    rt: Arc<Runtime>,
) -> AclDispatch {
    let (req_tx, mut req_rx) = channel::<RegistrationRequest>(10);

    rt.spawn(async move {
        let mut connections: HashMap<u16, Reassembler> = HashMap::new();
        let mut outbound = SelectAll::new();
        loop {
            select! {
                Some(req) = req_rx.recv() => {
                    let (out_tx, out_rx) = channel(10);
                    let (in_tx, in_rx) = channel(10);

                    let mtu = match req.bt {
                        Bluetooth::Classic => controller.acl_buffer_length.into(),
                        Bluetooth::Le => controller.le_buffer_length.into(),
                    };

                    assert!(connections.insert(req.handle, Reassembler::new(out_tx)).is_none());
                    outbound.push(fragmenting_stream(in_rx, mtu, req.handle, req.bt));

                    req.fut.send(Connection { rx: out_rx, tx: in_tx }).unwrap();
                },
                Some(packet) = consume(&acl.rx) => {
                    match connections.get_mut(&packet.get_handle()) {
                        Some(reassembler) => reassembler.on_packet(packet).await,
                        None if packet.get_handle() == QCOM_DEBUG_HANDLE => {},
                        None => info!("no acl for {}", packet.get_handle()),
                    }
                }
                Some(packet) = outbound.next() => {
                    acl.tx.send(packet).await.unwrap();
                }
            }
        }
    });

    AclDispatch { requests: req_tx }
}

async fn consume(rx: &Arc<Mutex<Receiver<AclPacket>>>) -> Option<AclPacket> {
    rx.lock().await.recv().await
}
