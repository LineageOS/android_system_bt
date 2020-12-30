//! Classic ACL manager

use bt_hci::{Address, CommandSender};
use bt_packets::hci::{
    ClockOffsetValid, CreateConnectionBuilder, CreateConnectionCancelBuilder,
    CreateConnectionRoleSwitch, PageScanRepetitionMode,
};
use gddi::{module, provides, Stoppable};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;

module! {
    classic_acl_module,
    providers {
        AclManager => provide_acl_manager,
    },
}

/// Classic ACL manager
#[derive(Clone, Stoppable)]
pub struct AclManager {
    req_tx: Sender<Request>,
}

impl AclManager {
    /// Connect to the specified address, or queue it if a connection is already pending
    pub async fn connect(&mut self, addr: Address) {
        self.req_tx.send(Request::Connect { addr }).await.unwrap();
    }

    /// Cancel the connection to the specified address, if it is pending
    pub async fn cancel_connect(&mut self, addr: Address) {
        let (tx, rx) = oneshot::channel();
        self.req_tx.send(Request::CancelConnect { addr, fut: tx }).await.unwrap();
        rx.await.unwrap();
    }
}

#[derive(Debug)]
enum Request {
    Connect { addr: Address },
    CancelConnect { addr: Address, fut: oneshot::Sender<()> },
}

#[provides]
async fn provide_acl_manager(mut hci: CommandSender, rt: Arc<Runtime>) -> AclManager {
    let (req_tx, mut req_rx) = channel::<Request>(10);

    rt.spawn(async move {
        let mut pending_connects: Vec<Address> = Vec::new();
        let mut outgoing_connect: Option<Address> = None;
        loop {
            select! {
                Some(req) = req_rx.recv() => {
                    match req {
                        Request::Connect { addr } => {
                            if outgoing_connect.is_none() {
                                outgoing_connect = Some(addr);
                                hci.send(build_create_connection(addr)).await;
                            } else {
                                pending_connects.insert(0, addr);
                            }
                        },
                        Request::CancelConnect { addr, fut } => {
                            pending_connects.retain(|p| *p != addr);
                            if outgoing_connect == Some(addr) {
                                hci.send(CreateConnectionCancelBuilder { bd_addr: addr }).await;
                            }
                            fut.send(()).unwrap();
                        }
                    }
                }
            }
        }
    });

    AclManager { req_tx }
}

fn build_create_connection(bd_addr: Address) -> CreateConnectionBuilder {
    CreateConnectionBuilder {
        bd_addr,
        packet_type: 0x4408 /* DM 1,3,5 */ | 0x8810, /*DH 1,3,5 */
        page_scan_repetition_mode: PageScanRepetitionMode::R1,
        clock_offset: 0,
        clock_offset_valid: ClockOffsetValid::Invalid,
        allow_role_switch: CreateConnectionRoleSwitch::AllowRoleSwitch,
    }
}
