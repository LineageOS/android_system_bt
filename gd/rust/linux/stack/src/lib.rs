//! Fluoride/GD Bluetooth stack.
//!
//! This crate provides the API implementation of the Fluoride/GD Bluetooth stack, independent of
//! any RPC projection.

#[macro_use]
extern crate num_derive;

pub mod bluetooth;
pub mod bluetooth_gatt;

use bt_topshim::btif::ffi;
use bt_topshim::btif::BtState;

use std::convert::TryInto;
use std::fmt::{Debug, Formatter, Result};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::{Receiver, Sender};

use crate::bluetooth::{Bluetooth, BtifBluetoothCallbacks};

/// Represents a Bluetooth address.
// TODO: Add support for LE random addresses.
#[derive(Copy, Clone)]
pub struct BDAddr {
    val: [u8; 6],
}

impl Debug for BDAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_fmt(format_args!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.val[0], self.val[1], self.val[2], self.val[3], self.val[4], self.val[5]
        ))
    }
}

impl ToString for BDAddr {
    fn to_string(&self) -> String {
        String::from(format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.val[0], self.val[1], self.val[2], self.val[3], self.val[4], self.val[5]
        ))
    }
}

impl BDAddr {
    /// Constructs a BDAddr from a vector of 6 bytes.
    fn from_byte_vec(raw_addr: &Vec<u8>) -> BDAddr {
        BDAddr { val: raw_addr.clone().try_into().unwrap() }
    }
}

/// Message types that are sent to the stack main dispatch loop.
pub enum Message {
    BluetoothAdapterStateChanged(BtState),
    BluetoothAdapterPropertiesChanged(i32, i32, Vec<ffi::BtProperty>),
    BluetoothCallbackDisconnected(u32),
}

/// Umbrella class for the Bluetooth stack.
pub struct Stack {}

impl Stack {
    /// Creates an mpsc channel for passing messages to the main dispatch loop.
    pub fn create_channel() -> (Sender<Message>, Receiver<Message>) {
        channel::<Message>(1)
    }

    /// Runs the main dispatch loop.
    pub async fn dispatch(mut rx: Receiver<Message>, bluetooth: Arc<Mutex<Bluetooth>>) {
        loop {
            let m = rx.recv().await;

            if m.is_none() {
                eprintln!("Message dispatch loop quit");
                break;
            }

            match m.unwrap() {
                Message::BluetoothAdapterStateChanged(state) => {
                    bluetooth.lock().unwrap().adapter_state_changed(state);
                }

                Message::BluetoothAdapterPropertiesChanged(status, num_properties, properties) => {
                    bluetooth.lock().unwrap().adapter_properties_changed(
                        status,
                        num_properties,
                        properties,
                    );
                }

                Message::BluetoothCallbackDisconnected(id) => {
                    bluetooth.lock().unwrap().callback_disconnected(id);
                }
            }
        }
    }
}

/// Signifies that the object may be a proxy to a remote RPC object.
///
/// An object that implements RPCProxy trait signifies that the object may be a proxy to a remote
/// RPC object. Therefore the object may be disconnected and thus should implement
/// `register_disconnect` to let others observe the disconnection event.
pub trait RPCProxy {
    fn register_disconnect(&mut self, f: Box<dyn Fn() + Send>);
}
