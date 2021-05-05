//! Bluetooth interface shim
//!
//! This is a shim interface for calling the C++ bluetooth interface via Rust.
//!

// TODO(abps): Remove this once callbacks are implemented
#![allow(unused_variables)]

use num_traits::FromPrimitive;
use std::sync::Arc;
use std::vec::Vec;

#[derive(FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum BtState {
    Off = 0,
    On,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq, PartialOrd, Debug)]
#[repr(i32)]
pub enum BtPropertyType {
    BdName = 0x1,
    BdAddr,
    Uuids,
    ClassOfDevice,
    TypeOfDevice,
    ServiceRecord,
    AdapterScanMode,
    AdapterBondedDevices,
    AdapterDiscoveryTimeout,
    RemoteFriendlyName,
    RemoteRssi,
    RemoteVersionInfo,
    LocalLeFeatures,
    LocalIoCaps,
    LocalIoCapsBle,
    DynamicAudioBuffer,

    Unknown = 0xFE,
    RemoteDeviceTimestamp = 0xFF,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum BtDiscoveryState {
    Stopped = 0x0,
    Started,
}

#[derive(FromPrimitive, ToPrimitive, PartialEq, PartialOrd)]
#[repr(i32)]
pub enum BtStatus {
    Success = 0,
    Fail,
    NotReady,
    NoMemory,
    Busy,
    Done,
    Unsupported,
    InvalidParam,
    Unhandled,
    AuthFailure,
    RemoteDeviceDown,
    AuthRejected,
    JniEnvironmentError,
    JniThreadAttachError,
    WakeLockError,

    // Any statuses that couldn't be cleanly converted
    Unknown = 0xff,
}

// FFI is a public module because we want Rust and C++ to share enums listed
// here. We redefine most of the Bluetooth structures we want to use because
// of memory management issues (for example, some api calls will free the
// memory passed into it). Bindgen was attempted but ultimately was not useful.
#[cxx::bridge(namespace = bluetooth::topshim::rust)]
pub mod ffi {

    pub struct BtPinCode {
        pin: [u8; 16],
    }

    pub struct BtProperty {
        prop_type: i32,
        len: i32,
        val: Vec<u8>,
    }

    pub struct BtUuid {
        uuid: [u8; 16],
    }

    pub struct RustRawAddress {
        address: [u8; 6],
    }

    unsafe extern "C++" {
        include!("btif/btif_shim.h");

        // Opaque type meant to represent C object for the Bluetooth interface.
        type BluetoothIntf;

        // Loads a unique pointer to the underlying interface
        fn Load() -> UniquePtr<BluetoothIntf>;

        fn Initialize(
            self: Pin<&mut Self>,
            callbacks: Box<RustCallbacks>,
            init_flags: Vec<String>,
        ) -> bool;

        fn CleanUp(&self);
        fn Enable(&self) -> i32;
        fn Disable(&self) -> i32;

        fn GetAdapterProperties(&self) -> i32;
        fn GetAdapterProperty(&self, prop_type: i32) -> i32;
        fn SetAdapterProperty(&self, prop: &BtProperty) -> i32;

        fn GetRemoteDeviceProperties(&self, address: &RustRawAddress) -> i32;
        fn GetRemoteDeviceProperty(&self, address: &RustRawAddress, prop_type: i32) -> i32;
        fn SetRemoteDeviceProperty(&self, address: &RustRawAddress, prop: &BtProperty) -> i32;

        fn GetRemoteServices(&self, address: &RustRawAddress) -> i32;

        fn StartDiscovery(&self) -> i32;
        fn CancelDiscovery(&self) -> i32;

        fn CreateBond(&self, address: &RustRawAddress, transport: i32) -> i32;
        // TODO(abps): Implement at P3
        // fn CreateBondOutOfBand(address: &RustRawAddress, transport: i32,
        //  oob_data: &BtOutOfBandData) -> i32;
        fn RemoveBond(&self, address: &RustRawAddress) -> i32;
        fn CancelBond(&self, address: &RustRawAddress) -> i32;

        fn GetConnectionState(&self, address: &RustRawAddress) -> i32;

        fn PinReply(
            &self,
            address: &RustRawAddress,
            accept: u8,
            pin_len: u8,
            code: &BtPinCode,
        ) -> i32;
        fn SspReply(
            &self,
            address: &RustRawAddress,
            ssp_variant: i32,
            accept: u8,
            passkey: u32,
        ) -> i32;

        // TODO(abps): Implement at P1
        // fn GetProfileInterface(profile_id: &str) -> Option<BtProfileInterface>;

        // TODO(abps): Implement at P2
        // fn dut_mode_configure(enable: u8) -> i32;
        // fn dut_mode_send(opcode: u16, buf: [u8], len: u8) -> i32;
        // fn le_test_mode(opcode: u16, buf: [u8], len: u8) -> i32;

        // TODO(abps): Implement at P1
        // fn SetOsCallouts(callouts: Box<RustOsCallouts>) -> i32;

        // TODO(abps): Implement at P3
        // fn ReadEnergyInfo(&self) -> i32;
        // fn Dump(fd: i32, args: &[str]);
        // fn DumpMetrics() -> String;
        // fn ConfigClear(&self) -> i32;
        // fn InteropDatabaseClear(&self);
        // fn InteropDatabaseAdd(&self, feature: u16, address: &RustRawAddress, match_len: u8);

        // TODO(abps): Implement at P1
        // fn GetAvrcpService() -> *mut AvrcpServiceInterface;

        // TODO(abps): Implement at P3
        // fn ObfuscateAddress(&self, address: &RustRawAddress) -> String;
        // fn GetMetricId(&self, address: &RustRawAddress) -> i32;
        // fn SetDynamicAudioBufferSize(&self, codec: i32, size: i32) -> i32;
    }

    extern "Rust" {
        type RustCallbacks;

        // Callbacks from C++ to Rust. The rust callbacks are stored when the
        // `BluetoothIntf` is initialized and consist of closures that take the
        // same parameters (without the first callbacks param).

        fn adapter_state_changed_callback(cb: &RustCallbacks, state: i32);
        fn adapter_properties_callback(
            cb: &RustCallbacks,
            status: i32,
            num_properties: i32,
            properties: Vec<BtProperty>,
        );
        fn remote_device_properties_callback(
            cb: &RustCallbacks,
            status: i32,
            address: RustRawAddress,
            num_properties: i32,
            properties: Vec<BtProperty>,
        );
        fn device_found_callback(
            cb: &RustCallbacks,
            num_properties: i32,
            properties: Vec<BtProperty>,
        );
        fn discovery_state_changed_callback(cb: &RustCallbacks, state: i32);
        fn pin_request_callback(
            cb: &RustCallbacks,
            remote_addr: RustRawAddress,
            bd_name: String,
            cod: u32,
            min_16_digit: bool,
        );
        fn ssp_request_callback(
            cb: &RustCallbacks,
            remote_addr: RustRawAddress,
            bd_name: String,
            cod: u32,
            variant: i32,
            pass_key: u32,
        );
        fn bond_state_changed_callback(
            cb: &RustCallbacks,
            status: i32,
            remote_addr: RustRawAddress,
            state: i32,
        );
        fn acl_state_changed_callback(
            cb: &RustCallbacks,
            status: i32,
            remote_addr: RustRawAddress,
            state: i32,
            hci_reason: i32,
        );

    }

    unsafe impl Box<RustCallbacks> {}
}

/// Rust struct of closures for all callbacks from C++.
///
/// Note: Due to the need to interop with the C interface, we cannot pass
///       additional state from C++ when calling these callbacks. Capture any
///       state you need in the closure provided to this struct.
pub struct BluetoothCallbacks {
    pub adapter_state_changed: Box<dyn Fn(BtState) + Send>,
    pub adapter_properties_changed: Box<dyn Fn(i32, i32, Vec<ffi::BtProperty>) + Send>,
    pub remote_device_properties_changed:
        Box<dyn Fn(i32, ffi::RustRawAddress, i32, Vec<ffi::BtProperty>) + Send>,
    pub device_found: Box<dyn Fn(i32, Vec<ffi::BtProperty>) + Send>,
    pub discovery_state_changed: Box<dyn Fn(BtDiscoveryState) + Send>,
    pub pin_request: Box<dyn Fn(ffi::RustRawAddress, String, u32, bool) + Send>,
    pub ssp_request: Box<dyn Fn(ffi::RustRawAddress, String, u32, i32, u32) + Send>,
    pub bond_state_changed: Box<dyn Fn(i32, ffi::RustRawAddress, i32) + Send>,
    pub acl_state_changed: Box<dyn Fn(i32, ffi::RustRawAddress, i32, i32) + Send>,
}

pub struct RustCallbacks {
    inner: Arc<BluetoothCallbacks>,
}

/// Rust interface to native Bluetooth.
pub struct BluetoothInterface {
    internal: cxx::UniquePtr<ffi::BluetoothIntf>,
}

impl BluetoothInterface {
    pub fn new() -> BluetoothInterface {
        BluetoothInterface { internal: ffi::Load() }
    }

    /// Initialize the BluetoothInterface shim (not strictly necessary as
    /// Load also initializes the interface).
    pub fn initialize(
        &mut self,
        callbacks: Arc<BluetoothCallbacks>,
        init_flags: Vec<String>,
    ) -> bool {
        //ffi::Initialize(*self.internal)
        self.internal
            .pin_mut()
            .Initialize(Box::new(RustCallbacks { inner: callbacks.clone() }), init_flags)
    }

    /// Enable the Bluetooth adapter. This triggers an adapter_state_changed callback.
    pub fn enable(&mut self) -> i32 {
        self.internal.Enable()
    }

    /// Disable the Bluetooth adapter. This triggers an adapter state changed callback.
    pub fn disable(&mut self) -> i32 {
        self.internal.Disable()
    }

    pub fn cleanup(&mut self) {
        self.internal.CleanUp()
    }

    pub fn get_adapter_properties(&mut self) -> i32 {
        self.internal.GetAdapterProperties()
    }

    pub fn get_adapter_property(&mut self, prop_type: i32) -> i32 {
        self.internal.GetAdapterProperty(prop_type)
    }

    pub fn set_adapter_property(&mut self, prop: &ffi::BtProperty) -> i32 {
        self.internal.SetAdapterProperty(prop)
    }

    //fn GetRemoteDeviceProperties(&self, address: &RustRawAddress) -> i32;
    //fn GetRemoteDeviceProperty(&self, address: &RustRawAddress, prop_type: i32) -> i32;
    //fn SetRemoteDeviceProperty(&self, address: &RustRawAddress, prop: &BtProperty) -> i32;
    //fn GetRemoteServices(&self, address: &RustRawAddress) -> i32;

    pub fn start_discovery(&mut self) -> i32 {
        self.internal.StartDiscovery()
    }
    pub fn cancel_discovery(&mut self) -> i32 {
        self.internal.CancelDiscovery()
    }

    pub fn create_bond(&mut self, address: &ffi::RustRawAddress, transport: i32) -> i32 {
        self.internal.CreateBond(address, transport)
    }
    pub fn remove_bond(&mut self, address: &ffi::RustRawAddress) -> i32 {
        self.internal.RemoveBond(address)
    }
    pub fn cancel_bond(&mut self, address: &ffi::RustRawAddress) -> i32 {
        self.internal.CancelBond(address)
    }

    pub fn get_connection_state(&mut self, address: &ffi::RustRawAddress) -> i32 {
        self.internal.GetConnectionState(address)
    }
}

unsafe impl Send for BluetoothInterface {}

fn adapter_state_changed_callback(cb: &RustCallbacks, state: i32) {
    let new_state = match BtState::from_i32(state) {
        Some(x) => x,
        None => BtState::Off,
    };
    (cb.inner.adapter_state_changed)(new_state);
}

fn adapter_properties_callback(
    cb: &RustCallbacks,
    status: i32,
    num_properties: i32,
    properties: Vec<ffi::BtProperty>,
) {
    (cb.inner.adapter_properties_changed)(status, num_properties, properties);
}

fn remote_device_properties_callback(
    cb: &RustCallbacks,
    status: i32,
    address: ffi::RustRawAddress,
    num_properties: i32,
    properties: Vec<ffi::BtProperty>,
) {
    (cb.inner.remote_device_properties_changed)(status, address, num_properties, properties);
}

fn device_found_callback(
    cb: &RustCallbacks,
    num_properties: i32,
    properties: Vec<ffi::BtProperty>,
) {
    (cb.inner.device_found)(num_properties, properties);
}
fn discovery_state_changed_callback(cb: &RustCallbacks, state: i32) {
    let new_state = match BtDiscoveryState::from_i32(state) {
        Some(x) => x,
        None => BtDiscoveryState::Stopped,
    };
    (cb.inner.discovery_state_changed)(new_state);
}
fn pin_request_callback(
    cb: &RustCallbacks,
    remote_addr: ffi::RustRawAddress,
    bd_name: String,
    cod: u32,
    min_16_digit: bool,
) {
    (cb.inner.pin_request)(remote_addr, bd_name, cod, min_16_digit);
}
fn ssp_request_callback(
    cb: &RustCallbacks,
    remote_addr: ffi::RustRawAddress,
    bd_name: String,
    cod: u32,
    variant: i32,
    pass_key: u32,
) {
    (cb.inner.ssp_request)(remote_addr, bd_name, cod, variant, pass_key);
}
fn bond_state_changed_callback(
    cb: &RustCallbacks,
    status: i32,
    remote_addr: ffi::RustRawAddress,
    state: i32,
) {
    (cb.inner.bond_state_changed)(status, remote_addr, state);
}
fn acl_state_changed_callback(
    cb: &RustCallbacks,
    status: i32,
    remote_addr: ffi::RustRawAddress,
    state: i32,
    hci_reason: i32,
) {
    (cb.inner.acl_state_changed)(status, remote_addr, state, hci_reason);
}
