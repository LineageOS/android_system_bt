//! HCI Hardware Abstraction Layer
//! Supports sending HCI commands to the HAL and receving
//! HCI events from the HAL
#[cfg(target_os = "android")]
#[macro_use]
extern crate lazy_static;

pub mod facade;
pub mod rootcanal_hal;
pub mod snoop;

#[cfg(target_os = "android")]
mod hidl_hal;

use bt_packet::{HciCommand, HciEvent, RawPacket};
use gddi::{module, Stoppable};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

#[cfg(target_os = "android")]
module! {
    hal_module,
    submodules {
        facade::hal_facade_module,
        hidl_hal::hidl_hal_module,
        snoop::snoop_module,
    },
}

#[cfg(not(target_os = "android"))]
module! {
    hal_module,
    submodules {
        facade::hal_facade_module,
        rootcanal_hal::rootcanal_hal_module,
        snoop::snoop_module,
    },
}
/// H4 packet header size
const H4_HEADER_SIZE: usize = 1;

/// HAL interface
/// This is used by the HCI module to send commands to the
/// HAL and receive events from the HAL
#[derive(Clone, Stoppable)]
pub struct HalExports {
    /// Transmit end of a channel used to send HCI commands
    pub cmd_tx: Sender<HciCommand>,
    /// Receive end of a channel used to receive HCI events
    pub evt_rx: Arc<Mutex<Receiver<HciEvent>>>,
    /// Transmit end of a channel used to send ACL data
    pub acl_tx: Sender<RawPacket>,
    /// Receive end of a channel used to receive ACL data
    pub acl_rx: Arc<Mutex<Receiver<RawPacket>>>,
}

mod internal {
    use bt_packet::{HciCommand, HciEvent, RawPacket};
    use gddi::Stoppable;
    use std::sync::Arc;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
    use tokio::sync::Mutex;

    #[derive(Clone, Stoppable)]
    pub struct RawHalExports {
        pub cmd_tx: UnboundedSender<HciCommand>,
        pub evt_rx: Arc<Mutex<UnboundedReceiver<HciEvent>>>,
        pub acl_tx: UnboundedSender<RawPacket>,
        pub acl_rx: Arc<Mutex<UnboundedReceiver<RawPacket>>>,
    }

    pub struct Hal {
        pub cmd_rx: UnboundedReceiver<HciCommand>,
        pub evt_tx: UnboundedSender<HciEvent>,
        pub acl_rx: UnboundedReceiver<RawPacket>,
        pub acl_tx: UnboundedSender<RawPacket>,
    }

    impl Hal {
        pub fn new() -> (RawHalExports, Self) {
            let (cmd_tx, cmd_rx) = unbounded_channel();
            let (evt_tx, evt_rx) = unbounded_channel();
            let (acl_down_tx, acl_down_rx) = unbounded_channel();
            let (acl_up_tx, acl_up_rx) = unbounded_channel();
            (
                RawHalExports {
                    cmd_tx,
                    evt_rx: Arc::new(Mutex::new(evt_rx)),
                    acl_tx: acl_down_tx,
                    acl_rx: Arc::new(Mutex::new(acl_up_rx)),
                },
                Self {
                    cmd_rx,
                    evt_tx,
                    acl_rx: acl_down_rx,
                    acl_tx: acl_up_tx,
                },
            )
        }
    }
}

/// Result type
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Errors that can be encountered while dealing with the HAL
#[derive(Error, Debug)]
pub enum HalError {
    /// Invalid rootcanal host error
    #[error("Invalid rootcanal host")]
    InvalidAddressError,
    /// Error while connecting to rootcanal
    #[error("Connection to rootcanal failed: {0}")]
    RootcanalConnectError(#[from] tokio::io::Error),
}
