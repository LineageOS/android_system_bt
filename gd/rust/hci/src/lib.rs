//! Host Controller Interface (HCI)

/// HCI errors
pub mod error;

/// HCI layer facade service
pub mod facade;

use bt_hal::HalExports;
use bt_packet::{HciCommand, HciEvent, RawPacket};
use error::Result;
use facade::facade_module;
use gddi::{module, provides};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{channel, Receiver, Sender, UnboundedReceiver, UnboundedSender};
use tokio::sync::{oneshot, Mutex};

module! {
    hci_module,
    submodules {
        facade_module,
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
    cmd: HciCommand,
    fut: oneshot::Sender<HciCommand>,
}

#[derive(Debug)]
struct PendingCommand {
    opcode: u16,
    fut: oneshot::Sender<HciCommand>,
}

/// HCI interface
#[derive(Clone)]
pub struct HciExports {
    cmd_tx: Sender<Command>,
    evt_handlers: Arc<Mutex<HashMap<u8, Sender<HciEvent>>>>,
    /// Transmit end of a channel used to send ACL data
    pub acl_tx: UnboundedSender<RawPacket>,
    /// Receive end of a channel used to receive ACL data
    pub acl_rx: Arc<Mutex<UnboundedReceiver<RawPacket>>>,
}

impl HciExports {
    async fn send(&mut self, cmd: HciCommand) -> Result<HciEvent> {
        let (tx, rx) = oneshot::channel::<HciEvent>();
        self.cmd_tx.send(Command { cmd, fut: tx }).await?;
        let event = rx.await?;
        Ok(event)
    }

    /// Enqueue an HCI command expecting a command complete
    /// response from the controller
    pub async fn enqueue_command_with_complete(&mut self, cmd: HciCommand) -> HciEvent {
        self.send(cmd).await.unwrap()
    }

    /// Enqueue an HCI command expecting a status response
    /// from the controller
    pub async fn enqueue_command_with_status(&mut self, cmd: HciCommand) -> HciEvent {
        self.send(cmd).await.unwrap()
    }

    /// Indicate interest in specific HCI events
    pub async fn register_event_handler(&mut self, evt_code: u8, sender: Sender<HciEvent>) {
        self.evt_handlers.lock().await.insert(evt_code, sender);
    }
}

async fn dispatch(
    evt_handlers: Arc<Mutex<HashMap<u8, Sender<HciEvent>>>>,
    evt_rx: Arc<Mutex<UnboundedReceiver<HciEvent>>>,
    cmd_tx: UnboundedSender<HciCommand>,
    mut cmd_rx: Receiver<Command>,
) {
    let mut pending_cmds: Vec<PendingCommand> = Vec::new();
    loop {
        select! {
            Some(evt) = consume(&evt_rx) => {
                let opcode = bt_packet::get_evt_opcode(&evt).unwrap();
                let evt_code = bt_packet::get_evt_code(&evt).unwrap();
                if let Some(pending_cmd) = remove_first(&mut pending_cmds, |entry| entry.opcode == opcode) {
                    pending_cmd.fut.send(evt).unwrap();
                } else if let Some(sender) = evt_handlers.lock().await.get(&evt_code) {
                    sender.send(evt).await.unwrap();
                }
            },
            Some(cmd) = cmd_rx.recv() => {
                pending_cmds.push(PendingCommand {
                    opcode: bt_packet::get_cmd_opcode(&cmd.cmd).unwrap(),
                    fut: cmd.fut,
                });
                cmd_tx.send(cmd.cmd).unwrap();
            },
            else => break,
        }
    }
}

async fn consume(evt_rx: &Arc<Mutex<UnboundedReceiver<HciEvent>>>) -> Option<HciEvent> {
    evt_rx.lock().await.recv().await
}

fn remove_first<T, P>(vec: &mut Vec<T>, predicate: P) -> Option<T>
where
    P: FnMut(&T) -> bool,
{
    if let Some(i) = vec.iter().position(predicate) {
        Some(vec.remove(i))
    } else {
        None
    }
}
