extern crate bt_shim;

use btstack::bluetooth::{IBluetooth, IBluetoothCallback};
use btstack::RPCProxy;

use dbus::nonblock::SyncConnection;
use dbus::strings::{BusName, Path};

use dbus_macros::{dbus_method, dbus_proxy_obj, generate_dbus_exporter};

use dbus_projection::DisconnectWatcher;

use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;

use crate::dbus_arg::DBusArg;

#[allow(dead_code)]
struct BluetoothCallbackDBus {}

#[dbus_proxy_obj(BluetoothCallback, "org.chromium.bluetooth.BluetoothCallback")]
impl IBluetoothCallback for BluetoothCallbackDBus {
    #[dbus_method("OnBluetoothStateChange")]
    fn on_bluetooth_state_changed(&self, prev_state: u32, new_state: u32) {}
    #[dbus_method("OnBluetoothAddressChanged")]
    fn on_bluetooth_address_changed(&self, addr: String) {}
}

#[allow(dead_code)]
struct IBluetoothDBus {}

#[generate_dbus_exporter(export_bluetooth_dbus_obj, "org.chromium.bluetooth.Bluetooth")]
impl IBluetooth for IBluetoothDBus {
    #[dbus_method("RegisterCallback")]
    fn register_callback(&mut self, callback: Box<dyn IBluetoothCallback + Send>) {}

    #[dbus_method("Enable")]
    fn enable(&mut self) -> bool {
        false
    }
    #[dbus_method("Disable")]
    fn disable(&mut self) -> bool {
        false
    }

    #[dbus_method("GetAddress")]
    fn get_address(&self) -> String {
        String::from("")
    }
}
