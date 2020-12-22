//! Hci shim

use bt_hci::facade::HciFacadeService;
use bt_packets::hci::{AclPacket, CommandPacket};
use std::sync::Arc;
use tokio::runtime::Runtime;

#[cxx::bridge(namespace = bluetooth::shim::rust)]
mod ffi {
    extern "C" {
        include!("callbacks/callbacks.h");

        type u8SliceCallback;
        fn Run(self: &u8SliceCallback, data: &[u8]);

        type u8SliceOnceCallback;
        fn Run(self: &u8SliceOnceCallback, data: &[u8]);
    }

    extern "Rust" {
        type Hci;

        fn hci_set_acl_callback(hci: &mut Hci, callback: UniquePtr<u8SliceCallback>);
        fn hci_set_evt_callback(hci: &mut Hci, callback: UniquePtr<u8SliceCallback>);
        fn hci_set_le_evt_callback(hci: &mut Hci, callback: UniquePtr<u8SliceCallback>);

        fn hci_send_command(hci: &mut Hci, data: &[u8], callback: UniquePtr<u8SliceOnceCallback>);
        fn hci_send_acl(hci: &mut Hci, data: &[u8]);
        fn hci_register_event(hci: &mut Hci, event: u8);
        fn hci_register_le_event(hci: &mut Hci, subevent: u8);
    }
}

// we take ownership when we get the callbacks
unsafe impl Send for ffi::u8SliceCallback {}
unsafe impl Send for ffi::u8SliceOnceCallback {}

pub struct Hci {
    internal: HciFacadeService,
    rt: Arc<Runtime>,
    acl_callback_set: bool,
    evt_callback_set: bool,
    le_evt_callback_set: bool,
}

impl Hci {
    pub fn new(rt: Arc<Runtime>, internal: HciFacadeService) -> Self {
        Self {
            rt,
            internal,
            acl_callback_set: false,
            evt_callback_set: false,
            le_evt_callback_set: false,
        }
    }
}

pub fn hci_send_command(
    hci: &mut Hci,
    data: &[u8],
    callback: cxx::UniquePtr<ffi::u8SliceOnceCallback>,
) {
    let packet = CommandPacket::parse(data).unwrap();
    let mut commands = hci.internal.commands.clone();
    hci.rt.spawn(async move {
        let resp = commands.send(packet).await.unwrap();
        callback.Run(&resp.to_bytes());
    });
}

pub fn hci_send_acl(hci: &mut Hci, data: &[u8]) {
    hci.rt.block_on(hci.internal.acl.tx.send(AclPacket::parse(data).unwrap())).unwrap();
}

pub fn hci_register_event(hci: &mut Hci, event: u8) {
    hci.rt.block_on(hci.internal.register_event(event.into()));
}

pub fn hci_register_le_event(hci: &mut Hci, subevent: u8) {
    hci.rt.block_on(hci.internal.register_le_event(subevent.into()));
}

pub fn hci_set_acl_callback(hci: &mut Hci, callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
    assert!(!hci.acl_callback_set);
    hci.acl_callback_set = true;

    let stream = hci.internal.acl.rx.clone();
    hci.rt.spawn(async move {
        while let Some(item) = stream.lock().await.recv().await {
            callback.Run(&item.to_bytes());
        }
    });
}

pub fn hci_set_evt_callback(hci: &mut Hci, callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
    assert!(!hci.evt_callback_set);
    hci.evt_callback_set = true;

    let stream = hci.internal.evt_rx.clone();
    hci.rt.spawn(async move {
        while let Some(item) = stream.lock().await.recv().await {
            callback.Run(&item.to_bytes());
        }
    });
}

pub fn hci_set_le_evt_callback(hci: &mut Hci, callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
    assert!(!hci.le_evt_callback_set);
    hci.le_evt_callback_set = true;

    let stream = hci.internal.le_evt_rx.clone();
    hci.rt.spawn(async move {
        while let Some(item) = stream.lock().await.recv().await {
            callback.Run(&item.to_bytes());
        }
    });
}
