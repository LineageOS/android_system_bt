//! BT snoop logger

use crate::internal::RawHalExports;
use crate::HalExports;
use bt_common::sys_prop;
use bt_packet::{HciCommand, HciEvent, RawPacket};
use bytes::{BufMut, Bytes, BytesMut};
use gddi::{module, provides, Stoppable};
use log::error;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs::{remove_file, rename, File};
use tokio::io::AsyncWriteExt;
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
    let (cmd_down_tx, mut cmd_down_rx) = channel::<HciCommand>(10);
    let (evt_up_tx, evt_up_rx) = channel::<HciEvent>(10);
    let (acl_down_tx, mut acl_down_rx) = channel::<RawPacket>(10);
    let (acl_up_tx, acl_up_rx) = channel::<RawPacket>(10);

    rt.spawn(async move {
        let mut logger = SnoopLogger::new(config).await;
        loop {
            select! {
                Some(evt) = consume(&hal_exports.evt_rx) => {
                    evt_up_tx.send(evt.clone()).await.unwrap();
                    logger.log(Type::Evt, Direction::Up, evt).await;
                },
                Some(cmd) = cmd_down_rx.recv() => {
                    hal_exports.cmd_tx.send(cmd.clone()).unwrap();
                    logger.log(Type::Cmd, Direction::Down, cmd).await;
                },
                Some(acl) = acl_down_rx.recv() => {
                    hal_exports.acl_tx.send(acl.clone()).unwrap();
                    logger.log(Type::Acl, Direction::Down, acl).await;
                },
                Some(acl) = consume(&hal_exports.acl_rx) => {
                    acl_up_tx.send(acl.clone()).await.unwrap();
                    logger.log(Type::Acl, Direction::Up, acl).await;
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

struct SnoopLogger {
    config: SnoopConfig,
    file: Option<File>,
    packets: u32,
}

// micros since 0000-01-01
const SNOOP_EPOCH_DELTA: u64 = 0x00dcddb30f2f8000;

impl SnoopLogger {
    async fn new(mut config: SnoopConfig) -> Self {
        // filtered snoop is not available at this time
        if let SnoopMode::Filtered = config.mode {
            config.mode = SnoopMode::Disabled;
        }

        remove_file(&config.path).await.ok();
        remove_file(config.path.clone() + ".last").await.ok();
        if let SnoopMode::Disabled = config.mode {
            remove_file(config.path.clone() + ".filtered").await.ok();
            remove_file(config.path.clone() + ".filtered.last")
                .await
                .ok();
        }

        let mut ret = Self {
            config,
            file: None,
            packets: 0,
        };
        ret.open_next_file().await;

        ret
    }

    async fn log(&mut self, t: Type, dir: Direction, bytes: Bytes) {
        if let SnoopMode::Disabled = self.config.mode {
            return;
        }

        let mut flags = 0;
        if let Direction::Up = dir {
            flags |= 0b01;
        }
        if let Type::Cmd | Type::Evt = t {
            flags |= 0b10;
        }

        let timestamp: u64 = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_micros(),
        )
        .unwrap()
            + SNOOP_EPOCH_DELTA;

        // Add one for the type byte
        let length = u32::try_from(bytes.len()).unwrap() + 1;

        let mut buffer = BytesMut::new();
        buffer.put_u32(length); // original length
        buffer.put_u32(length); // captured length
        buffer.put_u32(flags); // flags
        buffer.put_u32(0); // dropped packets
        buffer.put_u64(timestamp); // timestamp
        buffer.put_u8(t as u8); // type
        buffer.put(bytes);

        self.packets += 1;
        if self.packets > self.config.max_packets_per_file {
            self.open_next_file().await;
        }

        if let Some(file) = &mut self.file {
            if file.write_all(&buffer).await.is_err() {
                error!("Failed to write");
            }
            if file.flush().await.is_err() {
                error!("Failed to flush");
            }
        } else {
            panic!("Logging without a backing file");
        }
    }

    async fn close_file(&mut self) {
        if let Some(file) = &mut self.file {
            file.flush().await.ok();
            self.file = None;
        }
        self.packets = 0;
    }

    async fn open_next_file(&mut self) {
        self.close_file().await;

        rename(&self.config.path, self.config.path.clone() + ".last")
            .await
            .ok();
        let mut file = File::create(&self.config.path)
            .await
            .expect("could not open snoop log");
        file.write_all(b"btsnoop\x00\x00\x00\x00\x01\x00\x00\x03\xea")
            .await
            .expect("could not write snoop header");
        if file.flush().await.is_err() {
            error!("Failed to flush");
        }
        self.file = Some(file);
    }
}
