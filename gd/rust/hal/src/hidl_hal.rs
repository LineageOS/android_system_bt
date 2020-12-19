//! Implementation of the HAl that talks to BT controller over Android's HIDL
use crate::internal::{Hal, RawHalExports};
use bt_packets::hci::{AclPacket, CommandPacket, EventPacket};
use gddi::{module, provides};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::runtime::Runtime;
use tokio::select;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

module! {
    hidl_hal_module,
    providers {
        RawHalExports => provide_hidl_hal,
    }
}

#[provides]
async fn provide_hidl_hal(rt: Arc<Runtime>) -> RawHalExports {
    let (hal_exports, hal) = Hal::new();
    let (init_tx, mut init_rx) = unbounded_channel();
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
        include!("src/ffi/hidl.h");
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
    init_tx: UnboundedSender<()>,
    evt_tx: UnboundedSender<EventPacket>,
    acl_tx: UnboundedSender<AclPacket>,
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
        .send(EventPacket::parse(data).unwrap())
        .unwrap();
}

fn on_acl(data: &[u8]) {
    let callbacks = CALLBACKS.lock().unwrap();
    callbacks
        .as_ref()
        .unwrap()
        .acl_tx
        .send(AclPacket::parse(data).unwrap())
        .unwrap();
}

fn on_sco(_data: &[u8]) {}

async fn dispatch_outgoing(
    mut cmd_rx: UnboundedReceiver<CommandPacket>,
    mut acl_rx: UnboundedReceiver<AclPacket>,
) {
    loop {
        select! {
            Some(cmd) = cmd_rx.recv() => ffi::send_command(&cmd.to_bytes()),
            Some(acl) = acl_rx.recv() => ffi::send_acl(&acl.to_bytes()),
            else => break,
        }
    }
}
