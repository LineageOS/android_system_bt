//! Anything related to the adapter API (IBluetooth).

use bt_topshim::btif::ffi;
use bt_topshim::btif::{BluetoothCallbacks, BluetoothInterface, BtState};
use bt_topshim::topstack;

use btif_macros::btif_callbacks_generator;
use btif_macros::stack_message;

use num_traits::cast::ToPrimitive;
use num_traits::FromPrimitive;

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc::Sender;

use crate::{BDAddr, Message, RPCProxy};

/// Defines the adapter API.
pub trait IBluetooth {
    /// Adds a callback from a client who wishes to observe adapter events.
    fn register_callback(&mut self, callback: Box<dyn IBluetoothCallback + Send>);

    /// Enables the adapter.
    ///
    /// Returns true if the request is accepted.
    fn enable(&mut self) -> bool;

    /// Disables the adapter.
    ///
    /// Returns true if the request is accepted.
    fn disable(&mut self) -> bool;

    /// Returns the Bluetooth address of the local adapter.
    fn get_address(&self) -> String;
}

/// The interface for adapter callbacks registered through `IBluetooth::register_callback`.
pub trait IBluetoothCallback: RPCProxy {
    /// When any of the adapter states is changed.
    fn on_bluetooth_state_changed(&self, prev_state: u32, new_state: u32);

    /// When any of the adapter local address is changed.
    fn on_bluetooth_address_changed(&self, addr: String);
}

/// Implementation of the adapter API.
pub struct Bluetooth {
    intf: Arc<Mutex<BluetoothInterface>>,
    state: BtState,
    callbacks: Vec<(u32, Box<dyn IBluetoothCallback + Send>)>,
    callbacks_last_id: u32,
    tx: Sender<Message>,
    local_address: Option<BDAddr>,
}

impl Bluetooth {
    /// Constructs the IBluetooth implementation.
    pub fn new(tx: Sender<Message>, intf: Arc<Mutex<BluetoothInterface>>) -> Bluetooth {
        Bluetooth {
            tx,
            intf,
            state: BtState::Off,
            callbacks: vec![],
            callbacks_last_id: 0,
            local_address: None,
        }
    }

    fn update_local_address(&mut self, raw: &Vec<u8>) {
        self.local_address = Some(BDAddr::from_byte_vec(raw));

        for callback in &self.callbacks {
            callback.1.on_bluetooth_address_changed(self.local_address.unwrap().to_string());
        }
    }

    pub(crate) fn callback_disconnected(&mut self, id: u32) {
        self.callbacks.retain(|x| x.0 != id);
    }
}

#[btif_callbacks_generator(btif_bluetooth_callbacks, BluetoothCallbacks)]
pub(crate) trait BtifBluetoothCallbacks {
    #[stack_message(BluetoothAdapterStateChanged)]
    fn adapter_state_changed(&mut self, state: BtState);

    #[stack_message(BluetoothAdapterPropertiesChanged)]
    fn adapter_properties_changed(
        &mut self,
        status: i32,
        num_properties: i32,
        properties: Vec<ffi::BtProperty>,
    );
}

#[derive(FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(i32)]
#[derive(Debug)]
enum PropertyType {
    BDName = 0x01,
    BDAddr,
    Uuids,
    ClassOfDevice,
    TypeOfDevice,
    ServiceRecord,
    AdapterScanMode,
    AdapterBondedDevices,
    AdapterDiscoverableTimeout,
    RemoteFriendlyName,
    RemoteRssi,
    RemoteVersionInfo,
    RemoteLocalLeFeatures,
    RemoteDynamicAudioBuffer = 0x10,
    Unknown = 0x100,
}

impl BtifBluetoothCallbacks for Bluetooth {
    fn adapter_state_changed(&mut self, state: BtState) {
        for callback in &self.callbacks {
            callback
                .1
                .on_bluetooth_state_changed(self.state.to_u32().unwrap(), state.to_u32().unwrap());
        }

        self.state = state;
    }

    #[allow(unused_variables)]
    fn adapter_properties_changed(
        &mut self,
        status: i32,
        num_properties: i32,
        properties: Vec<ffi::BtProperty>,
    ) {
        if status != 0 {
            return;
        }

        for prop in properties {
            let prop_type = PropertyType::from_i32(prop.prop_type);

            if prop_type.is_none() {
                continue;
            }

            match prop_type.unwrap() {
                PropertyType::BDAddr => {
                    self.update_local_address(&prop.val);
                }
                _ => {}
            }
        }
    }
}

// TODO: Add unit tests for this implementation
impl IBluetooth for Bluetooth {
    fn register_callback(&mut self, mut callback: Box<dyn IBluetoothCallback + Send>) {
        let tx = self.tx.clone();

        // TODO: Refactor into a separate wrap-around id generator.
        self.callbacks_last_id += 1;
        let id = self.callbacks_last_id;

        callback.register_disconnect(Box::new(move || {
            let tx = tx.clone();
            topstack::get_runtime().spawn(async move {
                let _result = tx.send(Message::BluetoothCallbackDisconnected(id)).await;
            });
        }));

        self.callbacks.push((id, callback))
    }

    fn enable(&mut self) -> bool {
        self.intf.lock().unwrap().enable() == 0
    }

    fn disable(&mut self) -> bool {
        self.intf.lock().unwrap().disable() == 0
    }

    fn get_address(&self) -> String {
        match self.local_address {
            None => String::from(""),
            Some(addr) => addr.to_string(),
        }
    }
}
