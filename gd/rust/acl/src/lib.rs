//! ACL management

mod fragment;

use bt_common::Bluetooth::{self, Classic, Le};
use bt_hal::AclHal;
use bt_hci::{ControllerExports, EventRegistry};
use bt_packets::hci::EventChild::NumberOfCompletedPackets;
use bt_packets::hci::{AclPacket, EventCode};
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

struct ConnectionInternal {
    reassembler: Reassembler,
    bt: Bluetooth,
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
    mut events: EventRegistry,
    rt: Arc<Runtime>,
) -> AclDispatch {
    let (req_tx, mut req_rx) = channel::<RegistrationRequest>(10);

    rt.spawn(async move {
        let mut connections: HashMap<u16, ConnectionInternal> = HashMap::new();
        let mut classic_outbound = SelectAll::new();
        let mut classic_credits = controller.acl_buffers;
        let mut le_outbound = SelectAll::new();
        let mut le_credits: u16 = controller.le_buffers.into();

        let (evt_tx, mut evt_rx) = channel(3);
        events.register(EventCode::NumberOfCompletedPackets, evt_tx).await;

        loop {
            select! {
                Some(req) = req_rx.recv() => {
                    let (out_tx, out_rx) = channel(10);
                    let (in_tx, in_rx) = channel(10);

                    assert!(connections.insert(
                        req.handle,
                        ConnectionInternal {
                            reassembler: Reassembler::new(out_tx),
                            bt: req.bt,
                        }).is_none());

                    match req.bt {
                        Classic => {
                            classic_outbound.push(fragmenting_stream(
                                in_rx, controller.acl_buffer_length.into(), req.handle, req.bt));
                        },
                        Le => {
                            le_outbound.push(fragmenting_stream(
                                in_rx, controller.le_buffer_length.into(), req.handle, req.bt));
                        },
                    }

                    req.fut.send(Connection { rx: out_rx, tx: in_tx }).unwrap();
                },
                Some(packet) = consume(&acl.rx) => {
                    match connections.get_mut(&packet.get_handle()) {
                        Some(connection) => connection.reassembler.on_packet(packet).await,
                        None if packet.get_handle() == QCOM_DEBUG_HANDLE => {},
                        None => info!("no acl for {}", packet.get_handle()),
                    }
                },
                Some(packet) = classic_outbound.next(), if classic_credits > 0 => {
                    acl.tx.send(packet).await.unwrap();
                    classic_credits -= 1;
                },
                Some(packet) = le_outbound.next(), if le_credits > 0 => {
                    acl.tx.send(packet).await.unwrap();
                    le_credits -= 1;
                },
                Some(evt) = evt_rx.recv() => {
                    match evt.specialize() {
                        NumberOfCompletedPackets(evt) => {
                            for info in evt.get_completed_packets() {
                                match connections.get(&info.connection_handle) {
                                    Some(connection) => {
                                        let credits = info.host_num_of_completed_packets;
                                        match connection.bt {
                                            Classic => {
                                                classic_credits += credits;
                                                assert!(classic_credits <= controller.acl_buffers);
                                            },
                                            Le => {
                                                le_credits += credits;
                                                assert!(le_credits <= controller.le_buffers.into());
                                            },
                                        }
                                    },
                                    None => info!("dropping credits for unknown connection {}", info.connection_handle),
                                }
                            }
                        },
                        _ => unimplemented!(),
                    }
                },
            }
        }
    });

    AclDispatch { requests: req_tx }
}

async fn consume(rx: &Arc<Mutex<Receiver<AclPacket>>>) -> Option<AclPacket> {
    rx.lock().await.recv().await
}
