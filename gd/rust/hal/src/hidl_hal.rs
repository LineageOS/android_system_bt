//! Implementation of the HAl that talks to BT controller over Android's HIDL
use crate::{Hal, HalExports};
use bt_packet::{HciCommand, HciEvent, RawPacket};
use bytes::Bytes;
use gddi::{module, provides};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc;

module! {
    hidl_hal_module,
    providers {
        HalExports => provide_hidl_hal,
    }
}

#[provides]
async fn provide_hidl_hal(rt: Arc<Runtime>) -> HalExports {
    let (hal_exports, hal) = Hal::new();
    let (init_tx, mut init_rx) = mpsc::unbounded_channel();
    *CALLBACKS.lock().unwrap() = Some(Callbacks {
        init_tx,
        evt_tx: hal.evt_tx,
        acl_tx: hal.acl_tx,
    });
    ffi::start_hal();
    init_rx.recv().await.unwrap();

    rt.spawn(dispatch_outgoing(hal.cmd_rx, hal.acl_rx));

    hal_exports
}

#[cxx::bridge(namespace = bluetooth::hal)]
mod ffi {
    extern "C" {
        include!("src/hidl/interop.h");
        fn start_hal();
        fn stop_hal();
        fn send_command(data: &[u8]);
        fn send_acl(data: &[u8]);
        fn send_sco(data: &[u8]);
    }

    extern "Rust" {
        fn on_init_complete();
        fn on_event(data: &[u8]);
        fn on_acl(data: &[u8]);
        fn on_sco(data: &[u8]);
    }
}

struct Callbacks {
    init_tx: mpsc::UnboundedSender<()>,
    evt_tx: mpsc::UnboundedSender<HciEvent>,
    acl_tx: mpsc::UnboundedSender<RawPacket>,
}

lazy_static! {
    static ref CALLBACKS: Mutex<Option<Callbacks>> = Mutex::new(None);
}

fn on_init_complete() {
    let callbacks = CALLBACKS.lock().unwrap();
    callbacks.as_ref().unwrap().init_tx.send(()).unwrap();
}

fn on_event(data: &[u8]) {
    let callbacks = CALLBACKS.lock().unwrap();
    callbacks
        .as_ref()
        .unwrap()
        .evt_tx
        .send(Bytes::copy_from_slice(data))
        .unwrap();
}

fn on_acl(data: &[u8]) {
    let callbacks = CALLBACKS.lock().unwrap();
    callbacks
        .as_ref()
        .unwrap()
        .acl_tx
        .send(Bytes::copy_from_slice(data))
        .unwrap();
}

fn on_sco(_data: &[u8]) {}

async fn dispatch_outgoing(
    mut cmd_rx: mpsc::UnboundedReceiver<HciCommand>,
    mut acl_rx: mpsc::UnboundedReceiver<RawPacket>,
) {
    loop {
        select! {
            Some(cmd) = cmd_rx.recv() => ffi::send_command(&cmd),
            Some(acl) = acl_rx.recv() => ffi::send_acl(&acl),
            else => break,
        }
    }
}
