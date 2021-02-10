//! Host Controller Interface (HCI)

/// HCI controller info
pub mod controller;
/// HCI errors
pub mod error;
/// HCI layer facade service
pub mod facade;

pub use bt_hci_custom_types::*;
pub use controller::ControllerExports;

use bt_common::time::Alarm;
use bt_hal::ControlHal;
use bt_packets::hci::EventChild::{
    CommandComplete, CommandStatus, LeMetaEvent, MaxSlotsChange, PageScanRepetitionModeChange,
    VendorSpecificEvent,
};
use bt_packets::hci::{
    CommandExpectations, CommandPacket, ErrorCode, EventCode, EventPacket, LeMetaEventPacket,
    ResetBuilder, SubeventCode,
};
use error::Result;
use gddi::{module, part_out, provides, Stoppable};
use log::error;
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
        controller::controller_module,
    },
    providers {
        parts Hci => provide_hci,
    },
}

#[part_out]
#[derive(Clone, Stoppable)]
struct Hci {
    raw_commands: RawCommandSender,
    commands: CommandSender,
    events: EventRegistry,
}

#[provides]
async fn provide_hci(control: ControlHal, rt: Arc<Runtime>) -> Hci {
    let (cmd_tx, cmd_rx) = channel::<QueuedCommand>(10);
    let evt_handlers = Arc::new(Mutex::new(HashMap::new()));
    let le_evt_handlers = Arc::new(Mutex::new(HashMap::new()));

    rt.spawn(dispatch(
        evt_handlers.clone(),
        le_evt_handlers.clone(),
        control.rx,
        control.tx,
        cmd_rx,
    ));

    let raw_commands = RawCommandSender { cmd_tx };
    let mut commands = CommandSender { raw: raw_commands.clone() };

    assert!(
        commands.send(ResetBuilder {}).await.get_status() == ErrorCode::Success,
        "reset did not complete successfully"
    );

    Hci { raw_commands, commands, events: EventRegistry { evt_handlers, le_evt_handlers } }
}

#[derive(Debug)]
struct QueuedCommand {
    cmd: CommandPacket,
    fut: oneshot::Sender<EventPacket>,
}

/// Sends raw commands. Only useful for facades & shims, or wrapped as a CommandSender.
#[derive(Clone, Stoppable)]
pub struct RawCommandSender {
    cmd_tx: Sender<QueuedCommand>,
}

impl RawCommandSender {
    /// Send a command, but does not automagically associate the expected returning event type.
    ///
    /// Only really useful for facades & shims.
    pub async fn send(&mut self, cmd: CommandPacket) -> Result<EventPacket> {
        let (tx, rx) = oneshot::channel::<EventPacket>();
        self.cmd_tx.send(QueuedCommand { cmd, fut: tx }).await?;
        let event = rx.await?;
        Ok(event)
    }
}

/// Sends commands to the controller
#[derive(Clone, Stoppable)]
pub struct CommandSender {
    raw: RawCommandSender,
}

impl CommandSender {
    /// Send a command to the controller, getting an expected response back
    pub async fn send<T: Into<CommandPacket> + CommandExpectations>(
        &mut self,
        cmd: T,
    ) -> T::ResponseType {
        T::_to_response_type(self.raw.send(cmd.into()).await.unwrap())
    }
}

/// Provides ability to register and unregister for HCI events
#[derive(Clone, Stoppable)]
pub struct EventRegistry {
    evt_handlers: Arc<Mutex<HashMap<EventCode, Sender<EventPacket>>>>,
    le_evt_handlers: Arc<Mutex<HashMap<SubeventCode, Sender<LeMetaEventPacket>>>>,
}

impl EventRegistry {
    /// Indicate interest in specific HCI events
    pub async fn register(&mut self, code: EventCode, sender: Sender<EventPacket>) {
        match code {
            EventCode::CommandStatus
            | EventCode::CommandComplete
            | EventCode::LeMetaEvent
            | EventCode::PageScanRepetitionModeChange
            | EventCode::MaxSlotsChange
            | EventCode::VendorSpecific => panic!("{:?} is a protected event", code),
            _ => {
                assert!(
                    self.evt_handlers.lock().await.insert(code, sender).is_none(),
                    "A handler for {:?} is already registered",
                    code
                );
            }
        }
    }

    /// Remove interest in specific HCI events
    pub async fn unregister(&mut self, code: EventCode) {
        self.evt_handlers.lock().await.remove(&code);
    }

    /// Indicate interest in specific LE events
    pub async fn register_le(&mut self, code: SubeventCode, sender: Sender<LeMetaEventPacket>) {
        assert!(
            self.le_evt_handlers.lock().await.insert(code, sender).is_none(),
            "A handler for {:?} is already registered",
            code
        );
    }

    /// Remove interest in specific LE events
    pub async fn unregister_le(&mut self, code: SubeventCode) {
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
                            Some(QueuedCommand{cmd, fut}) if cmd.get_op_code() == this_opcode => {
                                if let Err(e) = fut.send(evt.into()) {
                                    error!("failure dispatching command status {:?}", e);
                                }
                            },
                            Some(QueuedCommand{cmd, ..}) => panic!("Waiting for {:?}, got {:?}", cmd.get_op_code(), this_opcode),
                            None => panic!("Unexpected status event with opcode {:?}", this_opcode),
                        }
                    },
                    CommandComplete(evt) => {
                        hci_timeout.cancel();
                        let this_opcode = evt.get_command_op_code();
                        match pending.take() {
                            Some(QueuedCommand{cmd, fut}) if cmd.get_op_code() == this_opcode => {
                                if let Err(e) = fut.send(evt.into()) {
                                    error!("failure dispatching command complete {:?}", e);
                                }
                            },
                            Some(QueuedCommand{cmd, ..}) => panic!("Waiting for {:?}, got {:?}", cmd.get_op_code(), this_opcode),
                            None => panic!("Unexpected complete event with opcode {:?}", this_opcode),
                        }
                    },
                    LeMetaEvent(evt) => {
                        let code = evt.get_subevent_code();
                        match le_evt_handlers.lock().await.get(&code) {
                            Some(sender) => {
                                if let Err(e) = sender.send(evt).await {
                                    error!("le meta event channel closed {:?}", e);
                                }
                            },
                            None => panic!("Unhandled le subevent {:?}", code),
                        }
                    },
                    PageScanRepetitionModeChange(_) => {},
                    MaxSlotsChange(_) => {},
                    VendorSpecificEvent(_) => {},
                    _ => {
                        let code = evt.get_event_code();
                        match evt_handlers.lock().await.get(&code) {
                            Some(sender) => {
                                if let Err(e) = sender.send(evt).await {
                                    error!("hci event channel closed {:?}", e);
                                }
                            },
                            None if code == EventCode::NumberOfCompletedPackets =>{},
                            None => panic!("Unhandled event {:?}", code),
                        }
                    },
                }
            },
            Some(queued) = cmd_rx.recv(), if pending.is_none() => {
                if let Err(e) = cmd_tx.send(queued.cmd.clone()).await {
                    error!("command queue closed: {:?}", e);
                }
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
