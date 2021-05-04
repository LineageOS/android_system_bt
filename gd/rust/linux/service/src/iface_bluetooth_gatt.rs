use btstack::bluetooth_gatt::{
    IBluetoothGatt, IScannerCallback, RSSISettings, ScanFilter, ScanSettings, ScanType,
};
use btstack::RPCProxy;

use dbus::arg::RefArg;

use dbus::nonblock::SyncConnection;
use dbus::strings::{BusName, Path};

use dbus_macros::{dbus_method, dbus_propmap, dbus_proxy_obj, generate_dbus_exporter};

use dbus_projection::impl_dbus_arg_enum;
use dbus_projection::DisconnectWatcher;

use num_traits::cast::{FromPrimitive, ToPrimitive};

use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use crate::dbus_arg::{DBusArg, DBusArgError};

#[allow(dead_code)]
struct ScannerCallbackDBus {}

#[dbus_proxy_obj(ScannerCallback, "org.chromium.bluetooth.ScannerCallback")]
impl IScannerCallback for ScannerCallbackDBus {
    #[dbus_method("OnScannerRegistered")]
    fn on_scanner_registered(&self, _status: i32, _scanner_id: i32) {}
}

#[dbus_propmap(RSSISettings)]
pub struct RSSISettingsDBus {
    low_threshold: i32,
    high_threshold: i32,
}

#[dbus_propmap(ScanSettings)]
struct ScanSettingsDBus {
    interval: i32,

    window: i32,

    #[dbus_propmap_field_enum]
    scan_type: ScanType,

    #[dbus_propmap_field_propmap]
    rssi_settings: RSSISettings,
}

impl_dbus_arg_enum!(ScanType);

#[dbus_propmap(ScanFilter)]
struct ScanFilterDBus {}

#[allow(dead_code)]
struct IBluetoothGattDBus {}

#[generate_dbus_exporter(export_bluetooth_gatt_dbus_obj, "org.chromium.bluetooth.BluetoothGatt")]
impl IBluetoothGatt for IBluetoothGattDBus {
    #[dbus_method("RegisterScanner")]
    fn register_scanner(&self, callback: Box<dyn IScannerCallback + Send>) {}

    #[dbus_method("UnregisterScanner")]
    fn unregister_scanner(&self, scanner_id: i32) {}

    #[dbus_method("StartScan")]
    fn start_scan(&self, scanner_id: i32, settings: ScanSettings, filters: Vec<ScanFilter>) {}

    #[dbus_method("StopScan")]
    fn stop_scan(&self, scanner_id: i32) {}
}
