//! Anything related to the GATT API (IBluetoothGatt).

use bt_topshim::btif::BluetoothInterface;

use std::sync::{Arc, Mutex};

/// Defines the GATT API.
pub trait IBluetoothGatt {
    fn register_scanner(&self, callback: Box<dyn IScannerCallback + Send>);

    fn unregister_scanner(&self, scanner_id: i32);

    fn start_scan(&self, scanner_id: i32, settings: ScanSettings, filters: Vec<ScanFilter>);
    fn stop_scan(&self, scanner_id: i32);
}

/// Interface for scanner callbacks to clients, passed to `IBluetoothGatt::register_scanner`.
pub trait IScannerCallback {
    /// When the `register_scanner` request is done.
    fn on_scanner_registered(&self, status: i32, scanner_id: i32);
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[repr(i32)]
/// Scan type configuration.
pub enum ScanType {
    Active = 0,
    Passive = 1,
}

impl Default for ScanType {
    fn default() -> Self {
        ScanType::Active
    }
}

/// Represents RSSI configurations for hardware offloaded scanning.
// TODO: This is still a placeholder struct, not yet complete.
#[derive(Debug, Default)]
pub struct RSSISettings {
    pub low_threshold: i32,
    pub high_threshold: i32,
}

/// Represents scanning configurations to be passed to `IBluetoothGatt::start_scan`.
#[derive(Debug, Default)]
pub struct ScanSettings {
    pub interval: i32,
    pub window: i32,
    pub scan_type: ScanType,
    pub rssi_settings: RSSISettings,
}

/// Represents a scan filter to be passed to `IBluetoothGatt::start_scan`.
#[derive(Debug, Default)]
pub struct ScanFilter {}

/// Implementation of the GATT API (IBluetoothGatt).
pub struct BluetoothGatt {
    _intf: Arc<Mutex<BluetoothInterface>>,
}

impl BluetoothGatt {
    /// Constructs a new IBluetoothGatt implementation.
    pub fn new(intf: Arc<Mutex<BluetoothInterface>>) -> BluetoothGatt {
        BluetoothGatt { _intf: intf }
    }
}

impl IBluetoothGatt for BluetoothGatt {
    fn register_scanner(&self, _callback: Box<dyn IScannerCallback + Send>) {
        // TODO: implement
    }

    fn unregister_scanner(&self, _scanner_id: i32) {
        // TODO: implement
    }

    fn start_scan(&self, _scanner_id: i32, _settings: ScanSettings, _filters: Vec<ScanFilter>) {
        // TODO: implement
    }

    fn stop_scan(&self, _scanner_id: i32) {
        // TODO: implement
    }
}
