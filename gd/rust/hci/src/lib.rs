//! Host Controller Interface (HCI)

/// HCI errors
pub mod error;

/// HCI layer facade service
pub mod facade;

use bt_hal::HalExports;
use bt_packets::hci::EventChild::{CommandComplete, CommandStatus};
use bt_packets::hci::{AclPacket, CommandPacket, EventCode, EventPacket, OpCode};
use error::Result;
use gddi::{module, provides, Stoppable};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{oneshot, Mutex};

module! {
    hci_module,
    submodules {
        facade::facade_module,
    },
    providers {
        HciExports => provide_hci,
    },
}

#[provides]
async fn provide_hci(hal_exports: HalExports, rt: Arc<Runtime>) -> HciExports {
    let (cmd_tx, cmd_rx) = channel::<Command>(10);
    let evt_handlers = Arc::new(Mutex::new(HashMap::new()));

    rt.spawn(dispatch(
        evt_handlers.clone(),
        hal_exports.evt_rx,
        hal_exports.cmd_tx,
        cmd_rx,
    ));

    HciExports {
        cmd_tx,
        evt_handlers,
        acl_tx: hal_exports.acl_tx,
        acl_rx: hal_exports.acl_rx,
    }
}

/// HCI command entry
/// Uses a oneshot channel to wait until the event corresponding
/// to the command is received
#[derive(Debug)]
struct Command {
    cmd: CommandPacket,
    fut: oneshot::Sender<EventPacket>,
}

#[derive(Debug)]
struct PendingCommand {
    opcode: OpCode,
    fut: oneshot::Sender<EventPacket>,
}

/// HCI interface
#[derive(Clone, Stoppable)]
pub struct HciExports {
    cmd_tx: Sender<Command>,
    evt_handlers: Arc<Mutex<HashMap<EventCode, Sender<EventPacket>>>>,
    /// Transmit end of a channel used to send ACL data
    pub acl_tx: Sender<AclPacket>,
    /// Receive end of a channel used to receive ACL data
    pub acl_rx: Arc<Mutex<Receiver<AclPacket>>>,
}

impl HciExports {
    async fn send(&mut self, cmd: CommandPacket) -> Result<EventPacket> {
        let (tx, rx) = oneshot::channel::<EventPacket>();
        self.cmd_tx.send(Command { cmd, fut: tx }).await?;
        let event = rx.await?;
        Ok(event)
    }

    /// Enqueue an HCI command expecting a command complete
    /// response from the controller
    pub async fn enqueue_command_with_complete(&mut self, cmd: CommandPacket) -> EventPacket {
        self.send(cmd).await.unwrap()
    }

    /// Enqueue an HCI command expecting a status response
    /// from the controller
    pub async fn enqueue_command_with_status(&mut self, cmd: CommandPacket) -> EventPacket {
        self.send(cmd).await.unwrap()
    }

    /// Indicate interest in specific HCI events
    pub async fn register_event_handler(
        &mut self,
        evt_code: EventCode,
        sender: Sender<EventPacket>,
    ) {
        self.evt_handlers.lock().await.insert(evt_code, sender);
    }
}

async fn dispatch(
    evt_handlers: Arc<Mutex<HashMap<EventCode, Sender<EventPacket>>>>,
    evt_rx: Arc<Mutex<Receiver<EventPacket>>>,
    cmd_tx: Sender<CommandPacket>,
    mut cmd_rx: Receiver<Command>,
) {
    let mut pending_cmd: Option<PendingCommand> = None;
    loop {
        select! {
            Some(evt) = consume(&evt_rx) => {
                match evt.specialize() {
                    CommandStatus(evt) => {
                        let opcode = *evt.get_command_op_code();
                        assert!(pending_cmd.is_some(), "Unexpected status event with opcode {:?}", opcode);
                        let pending = pending_cmd.take().unwrap();
                        assert!(pending.opcode == opcode, "Waiting for {:?}, got {:?}", pending.opcode, opcode);
                        pending.fut.send(evt.into()).unwrap();
                    },
                    CommandComplete(evt) => {
                        let opcode = *evt.get_command_op_code();
                        assert!(pending_cmd.is_some(), "Unexpected complete event with opcode {:?}", opcode);
                        let pending = pending_cmd.take().unwrap();
                        assert!(pending.opcode == opcode, "Waiting for {:?}, got {:?}", pending.opcode, opcode);
                        pending.fut.send(evt.into()).unwrap();
                    },
                    _ => {
                        if let Some(sender) = evt_handlers.lock().await.get(evt.get_event_code()) {
                            sender.send(evt).await.unwrap();
                        }
                    },
                }
            },
            Some(cmd) = cmd_rx.recv(), if pending_cmd.is_none() => {
                pending_cmd = Some(PendingCommand {
                    opcode: *cmd.cmd.get_op_code(),
                    fut: cmd.fut,
                });
                cmd_tx.send(cmd.cmd).await.unwrap();
            },
            else => break,
        }
    }
}

async fn consume(evt_rx: &Arc<Mutex<Receiver<EventPacket>>>) -> Option<EventPacket> {
    evt_rx.lock().await.recv().await
}
