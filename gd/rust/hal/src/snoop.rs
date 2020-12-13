//! BT snoop logger

use crate::internal::RawHalExports;
use crate::HalExports;
use bt_common::sys_prop;
use gddi::{module, provides, Stoppable};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{channel, UnboundedReceiver};
use tokio::sync::Mutex;

/// The different modes snoop logging can be in
#[derive(Clone)]
pub enum SnoopMode {
    /// All logs disabled
    Disabled,
    /// Only sanitized logs
    Filtered,
    /// Log everything
    Full,
}

/// There was an error parsing the mode from a string
pub struct SnoopModeParseError;

impl std::str::FromStr for SnoopMode {
    type Err = SnoopModeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(SnoopMode::Disabled),
            "filtered" => Ok(SnoopMode::Filtered),
            "full" => Ok(SnoopMode::Full),
            _ => Err(SnoopModeParseError),
        }
    }
}

/// All snoop logging config
#[derive(Clone, Stoppable)]
pub struct SnoopConfig {
    path: String,
    max_packets_per_file: u32,
    mode: SnoopMode,
}

impl SnoopConfig {
    /// Constructs a new snoop config
    pub fn new() -> Self {
        Self {
            path: "/data/misc/bluetooth/logs/btsnoop_hci.log".to_string(),
            max_packets_per_file: sys_prop::get_u32("persist.bluetooth.btsnoopsize")
                .unwrap_or(0xFFFF),
            mode: get_configured_snoop_mode()
                .parse()
                .unwrap_or(SnoopMode::Disabled),
        }
    }

    /// Overwrites the laoded log path with the provided one
    pub fn set_path(&mut self, value: String) {
        self.path = value;
    }

    /// Overwrites the loaded mode with the provided one
    pub fn set_mode(&mut self, value: SnoopMode) {
        self.mode = value;
    }
}

impl Default for SnoopConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn get_configured_snoop_mode() -> String {
    sys_prop::get("persist.bluetooth.btsnooplogmode").unwrap_or(if sys_prop::get_debuggable() {
        sys_prop::get("persist.bluetooth.btsnoopdefaultmode").unwrap_or_default()
    } else {
        String::default()
    })
}

module! {
    snoop_module,
    providers {
        HalExports => provide_snooped_hal,
    },
}

#[provides]
async fn provide_snooped_hal(
    config: SnoopConfig,
    hal_exports: RawHalExports,
    rt: Arc<Runtime>,
) -> HalExports {
    let (cmd_down_tx, mut cmd_down_rx) = channel(10);
    let (evt_up_tx, evt_up_rx) = channel(10);
    let (acl_down_tx, mut acl_down_rx) = channel(10);
    let (acl_up_tx, acl_up_rx) = channel(10);

    rt.spawn(async move {
        let logger = SnoopLogger::new(config);
        loop {
            select! {
                Some(evt) = consume(&hal_exports.evt_rx) => {
                    logger.log(Type::Evt, Direction::Up, &evt);
                    evt_up_tx.send(evt).await.unwrap();
                },
                Some(cmd) = cmd_down_rx.recv() => {
                    logger.log(Type::Cmd, Direction::Down, &cmd);
                    hal_exports.cmd_tx.send(cmd).unwrap();
                },
                Some(acl) = acl_down_rx.recv() => {
                    logger.log(Type::Acl, Direction::Down, &acl);
                    hal_exports.acl_tx.send(acl).unwrap();
                },
                Some(acl) = consume(&hal_exports.acl_rx) => {
                    logger.log(Type::Acl, Direction::Up, &acl);
                    acl_up_tx.send(acl).await.unwrap();
                }
            }
        }
    });

    HalExports {
        cmd_tx: cmd_down_tx,
        evt_rx: Arc::new(Mutex::new(evt_up_rx)),
        acl_tx: acl_down_tx,
        acl_rx: Arc::new(Mutex::new(acl_up_rx)),
    }
}

async fn consume<T>(rx: &Arc<Mutex<UnboundedReceiver<T>>>) -> Option<T> {
    rx.lock().await.recv().await
}

#[allow(unused)]
enum Type {
    Cmd = 1,
    Acl,
    Sco,
    Evt,
    Iso,
}

enum Direction {
    Up,
    Down,
}

struct SnoopLogger;

impl SnoopLogger {
    fn new(_config: SnoopConfig) -> Self {
        Self {}
    }

    fn log(&self, _t: Type, _dir: Direction, _bytes: &bytes::Bytes) {}
}
