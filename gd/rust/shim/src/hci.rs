//! Hci shim

use bt_packets::hci::{
    AclPacket, CommandPacket, EventCode, EventPacket, LeMetaEventPacket, SubeventCode,
};
use num_traits::FromPrimitive;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;

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
    rt: Arc<Runtime>,
    internal: bt_hci::HciExports,
    acl_callback_set: bool,
    evt_callback_set: bool,
    le_evt_callback_set: bool,
    evt_tx: Sender<EventPacket>,
    evt_rx: Arc<Mutex<Receiver<EventPacket>>>,
    le_evt_tx: Sender<LeMetaEventPacket>,
    le_evt_rx: Arc<Mutex<Receiver<LeMetaEventPacket>>>,
}

impl Hci {
    pub fn new(rt: Arc<Runtime>, internal: bt_hci::HciExports) -> Self {
        let (evt_tx, evt_rx) = channel::<EventPacket>(10);
        let (le_evt_tx, le_evt_rx) = channel::<LeMetaEventPacket>(10);
        Self {
            rt,
            internal,
            acl_callback_set: false,
            evt_callback_set: false,
            le_evt_callback_set: false,
            evt_tx,
            evt_rx: Arc::new(Mutex::new(evt_rx)),
            le_evt_tx,
            le_evt_rx: Arc::new(Mutex::new(le_evt_rx)),
        }
    }
}

pub fn hci_send_command(
    hci: &mut Hci,
    data: &[u8],
    callback: cxx::UniquePtr<ffi::u8SliceOnceCallback>,
) {
    let packet = CommandPacket::parse(data).unwrap();
    let mut clone_internal = hci.internal.clone();
    hci.rt.spawn(async move {
        let resp = clone_internal.send_raw(packet).await.unwrap();
        callback.Run(&resp.to_bytes());
    });
}

pub fn hci_send_acl(hci: &mut Hci, data: &[u8]) {
    hci.rt.block_on(hci.internal.acl_tx.send(AclPacket::parse(data).unwrap())).unwrap();
}

pub fn hci_register_event(hci: &mut Hci, event: u8) {
    hci.rt.block_on(
        hci.internal.register_event_handler(EventCode::from_u8(event).unwrap(), hci.evt_tx.clone()),
    );
}

pub fn hci_register_le_event(hci: &mut Hci, subevent: u8) {
    hci.rt.block_on(hci.internal.register_le_event_handler(
        SubeventCode::from_u8(subevent).unwrap(),
        hci.le_evt_tx.clone(),
    ));
}

pub fn hci_set_acl_callback(hci: &mut Hci, callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
    assert!(!hci.acl_callback_set);
    hci.acl_callback_set = true;

    let stream = hci.internal.acl_rx.clone();
    hci.rt.spawn(async move {
        while let Some(item) = stream.lock().await.recv().await {
            callback.Run(&item.to_bytes());
        }
    });
}

pub fn hci_set_evt_callback(hci: &mut Hci, callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
    assert!(!hci.evt_callback_set);
    hci.evt_callback_set = true;

    let stream = hci.evt_rx.clone();
    hci.rt.spawn(async move {
        while let Some(item) = stream.lock().await.recv().await {
            callback.Run(&item.to_bytes());
        }
    });
}

pub fn hci_set_le_evt_callback(hci: &mut Hci, callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
    assert!(!hci.le_evt_callback_set);
    hci.le_evt_callback_set = true;

    let stream = hci.le_evt_rx.clone();
    hci.rt.spawn(async move {
        while let Some(item) = stream.lock().await.recv().await {
            callback.Run(&item.to_bytes());
        }
    });
}
