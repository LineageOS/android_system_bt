//! Stack management

use bt_common::init_flags;
use bt_main::Stack;
use std::sync::Arc;
use tokio::runtime::Runtime;

#[cxx::bridge(namespace = bluetooth::rust::stack)]
mod ffi {
    extern "Rust" {
        type Stack;

        fn create() -> Box<Stack>;
        fn start(stack: &mut Stack);
        fn stop(stack: &mut Stack);
    }
}

pub fn create() -> Box<Stack> {
    assert!(init_flags::gd_rust_is_enabled());

    let rt = Arc::new(Runtime::new().unwrap());
    let local_rt = rt.clone();
    rt.block_on(async move {
        let stack = Stack::new(local_rt).await;
        stack.use_default_snoop().await;

        Box::new(stack)
    })
}

pub fn start(stack: &mut Stack) {
    assert!(init_flags::gd_rust_is_enabled());

    if init_flags::gd_hci_is_enabled() {
        stack.get_blocking::<bt_hci::HciExports>();
    }
}

pub fn stop(stack: &mut Stack) {
    assert!(init_flags::gd_rust_is_enabled());

    stack.stop_blocking();
}
