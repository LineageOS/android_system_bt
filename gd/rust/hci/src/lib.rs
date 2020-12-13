//! Host Controller Interface (HCI)

/// HCI errors
pub mod error;

/// HCI layer facade service
pub mod facade;

use bt_common::time::Alarm;
use bt_hal::HalExports;
use bt_packets::hci::EventChild::{
    CommandComplete, CommandStatus, LeMetaEvent, MaxSlotsChange, PageScanRepetitionModeChange,
    VendorSpecificEvent,
};
use bt_packets::hci::{
    AclPacket, CommandExpectations, CommandPacket, ErrorCode, EventCode, EventPacket,
    LeMetaEventPacket, ResetBuilder, SubeventCode,
};
use error::Result;
use gddi::{module, provides, Stoppable};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
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
    let (cmd_tx, cmd_rx) = channel::<QueuedCommand>(10);
    let evt_handlers = Arc::new(Mutex::new(HashMap::new()));
    let le_evt_handlers = Arc::new(Mutex::new(HashMap::new()));

    rt.spawn(dispatch(
        evt_handlers.clone(),
        le_evt_handlers.clone(),
        hal_exports.evt_rx,
        hal_exports.cmd_tx,
        cmd_rx,
    ));

    let mut exports = HciExports {
        cmd_tx,
        evt_handlers,
        le_evt_handlers,
        acl_tx: hal_exports.acl_tx,
        acl_rx: hal_exports.acl_rx,
    };

    assert!(
        exports.send(ResetBuilder {}.build()).await.get_status() == ErrorCode::Success,
        "reset did not complete successfully"
    );

    exports
}

#[derive(Debug)]
struct QueuedCommand {
    cmd: CommandPacket,
    fut: oneshot::Sender<EventPacket>,
}

/// HCI interface
#[derive(Clone, Stoppable)]
pub struct HciExports {
    cmd_tx: Sender<QueuedCommand>,
    evt_handlers: Arc<Mutex<HashMap<EventCode, Sender<EventPacket>>>>,
    le_evt_handlers: Arc<Mutex<HashMap<SubeventCode, Sender<LeMetaEventPacket>>>>,
    /// Transmit end of a channel used to send ACL data
    pub acl_tx: Sender<AclPacket>,
    /// Receive end of a channel used to receive ACL data
    pub acl_rx: Arc<Mutex<Receiver<AclPacket>>>,
}

impl HciExports {
    async fn send_raw(&mut self, cmd: CommandPacket) -> Result<EventPacket> {
        let (tx, rx) = oneshot::channel::<EventPacket>();
        self.cmd_tx.send(QueuedCommand { cmd, fut: tx }).await?;
        let event = rx.await?;
        Ok(event)
    }

    /// Send a command to the controller, getting an expected response back
    pub async fn send<T: Into<CommandPacket> + CommandExpectations>(
        &mut self,
        cmd: T,
    ) -> T::ResponseType {
        T::_to_response_type(self.send_raw(cmd.into()).await.unwrap())
    }

    /// Indicate interest in specific HCI events
    pub async fn register_event_handler(&mut self, code: EventCode, sender: Sender<EventPacket>) {
        match code {
            EventCode::CommandStatus
            | EventCode::CommandComplete
            | EventCode::LeMetaEvent
            | EventCode::PageScanRepetitionModeChange
            | EventCode::MaxSlotsChange
            | EventCode::VendorSpecific => panic!("{:?} is a protected event", code),
            _ => {
                assert!(
                    self.evt_handlers
                        .lock()
                        .await
                        .insert(code, sender)
                        .is_none(),
                    "A handler for {:?} is already registered",
                    code
                );
            }
        }
    }

    /// Remove interest in specific HCI events
    pub async fn unregister_event_handler(&mut self, code: EventCode) {
        self.evt_handlers.lock().await.remove(&code);
    }

    /// Indicate interest in specific LE events
    pub async fn register_le_event_handler(
        &mut self,
        code: SubeventCode,
        sender: Sender<LeMetaEventPacket>,
    ) {
        assert!(
            self.le_evt_handlers
                .lock()
                .await
                .insert(code, sender)
                .is_none(),
            "A handler for {:?} is already registered",
            code
        );
    }

    /// Remove interest in specific LE events
    pub async fn unregister_le_event_handler(&mut self, code: SubeventCode) {
        self.le_evt_handlers.lock().await.remove(&code);
    }
}

async fn dispatch(
    evt_handlers: Arc<Mutex<HashMap<EventCode, Sender<EventPacket>>>>,
    le_evt_handlers: Arc<Mutex<HashMap<SubeventCode, Sender<LeMetaEventPacket>>>>,
    evt_rx: Arc<Mutex<Receiver<EventPacket>>>,
    cmd_tx: Sender<CommandPacket>,
    mut cmd_rx: Receiver<QueuedCommand>,
) {
    let mut pending: Option<QueuedCommand> = None;
    let mut hci_timeout = Alarm::new();
    loop {
        select! {
            Some(evt) = consume(&evt_rx) => {
                match evt.specialize() {
                    CommandStatus(evt) => {
                        hci_timeout.cancel();
                        let this_opcode = evt.get_command_op_code();
                        match pending.take() {
                            Some(QueuedCommand{cmd, fut}) if cmd.get_op_code() == this_opcode  => fut.send(evt.into()).unwrap(),
                            Some(QueuedCommand{cmd, ..}) => panic!("Waiting for {:?}, got {:?}", cmd.get_op_code(), this_opcode),
                            None => panic!("Unexpected status event with opcode {:?}", this_opcode),
                        }
                    },
                    CommandComplete(evt) => {
                        hci_timeout.cancel();
                        let this_opcode = evt.get_command_op_code();
                        match pending.take() {
                            Some(QueuedCommand{cmd, fut}) if cmd.get_op_code() == this_opcode  => fut.send(evt.into()).unwrap(),
                            Some(QueuedCommand{cmd, ..}) => panic!("Waiting for {:?}, got {:?}", cmd.get_op_code(), this_opcode),
                            None => panic!("Unexpected complete event with opcode {:?}", this_opcode),
                        }
                    },
                    LeMetaEvent(evt) => {
                        let code = evt.get_subevent_code();
                        match le_evt_handlers.lock().await.get(&code) {
                            Some(sender) => sender.send(evt).await.unwrap(),
                            None => panic!("Unhandled le subevent {:?}", code),
                        }
                    },
                    PageScanRepetitionModeChange(_) => {},
                    MaxSlotsChange(_) => {},
                    VendorSpecificEvent(_) => {},
                    _ => {
                        let code = evt.get_event_code();
                        match evt_handlers.lock().await.get(&code) {
                            Some(sender) => sender.send(evt).await.unwrap(),
                            None => panic!("Unhandled le subevent {:?}", code),
                        }
                    },
                }
            },
            Some(queued) = cmd_rx.recv(), if pending.is_none() => {
                cmd_tx.send(queued.cmd.clone()).await.unwrap();
                hci_timeout.reset(Duration::from_secs(2));
                pending = Some(queued);
            },
            _ = hci_timeout.expired() => panic!("Timed out waiting for {:?}", pending.unwrap().cmd.get_op_code()),
            else => break,
        }
    }
}

async fn consume(evt_rx: &Arc<Mutex<Receiver<EventPacket>>>) -> Option<EventPacket> {
    evt_rx.lock().await.recv().await
}
