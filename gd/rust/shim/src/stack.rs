//! Stack management

use crate::hci::Hci;
use bt_common::init_flags;
use bt_main::Stack;
use std::sync::Arc;
use tokio::runtime::Runtime;

#[cxx::bridge(namespace = bluetooth::shim::rust)]
mod ffi {
    extern "Rust" {
        type Stack;
        type Hci;

        fn stack_create() -> Box<Stack>;
        fn stack_start(stack: &mut Stack);
        fn stack_stop(stack: &mut Stack);

        fn get_hci(stack: &mut Stack) -> Box<Hci>;
    }
}

pub fn stack_create() -> Box<Stack> {
    assert!(init_flags::gd_rust_is_enabled());

    let rt = Arc::new(Runtime::new().unwrap());
    let local_rt = rt.clone();
    rt.block_on(async move {
        let stack = Stack::new(local_rt).await;
        stack.use_default_snoop().await;

        Box::new(stack)
    })
}

pub fn stack_start(stack: &mut Stack) {
    assert!(init_flags::gd_rust_is_enabled());

    if init_flags::gd_hci_is_enabled() {
        stack.get_blocking::<bt_hci::HciExports>();
    }
}

pub fn stack_stop(stack: &mut Stack) {
    assert!(init_flags::gd_rust_is_enabled());

    stack.stop_blocking();
}

pub fn get_hci(stack: &mut Stack) -> Box<Hci> {
    assert!(init_flags::gd_rust_is_enabled());
    assert!(init_flags::gd_hci_is_enabled());

    Box::new(Hci::new(stack.get_runtime(), stack.get_blocking::<bt_hci::HciExports>()))
}
