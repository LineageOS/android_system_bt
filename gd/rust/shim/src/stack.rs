//! Stack management

use crate::controller::Controller;
use crate::hci::Hci;
use bt_common::init_flags;
use bt_main::Stack;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

lazy_static! {
    pub static ref RUNTIME: Arc<Runtime> = Arc::new(
        Builder::new_multi_thread().worker_threads(1).max_threads(1).enable_all().build().unwrap()
    );
}

#[cxx::bridge(namespace = bluetooth::shim::rust)]
mod ffi {
    extern "Rust" {
        type Stack;
        type Hci;
        type Controller;

        fn stack_create() -> Box<Stack>;
        fn stack_start(stack: &mut Stack);
        fn stack_stop(stack: &mut Stack);

        fn get_hci(stack: &mut Stack) -> Box<Hci>;
        fn get_controller(stack: &mut Stack) -> Box<Controller>;
    }
}

pub fn stack_create() -> Box<Stack> {
    assert!(init_flags::gd_rust_is_enabled());

    let local_rt = RUNTIME.clone();
    RUNTIME.block_on(async move {
        let stack = Stack::new(local_rt).await;
        stack.use_default_snoop().await;

        Box::new(stack)
    })
}

pub fn stack_start(_stack: &mut Stack) {
    assert!(init_flags::gd_rust_is_enabled());
}

pub fn stack_stop(stack: &mut Stack) {
    assert!(init_flags::gd_rust_is_enabled());

    stack.stop_blocking();
}

pub fn get_hci(stack: &mut Stack) -> Box<Hci> {
    assert!(init_flags::gd_rust_is_enabled());
    assert!(init_flags::gd_hci_is_enabled());

    Box::new(Hci::new(
        stack.get_runtime(),
        stack.get_blocking::<bt_hci::facade::HciFacadeService>(),
    ))
}

pub fn get_controller(stack: &mut Stack) -> Box<Controller> {
    assert!(init_flags::gd_rust_is_enabled());
    assert!(init_flags::gd_controller_is_enabled());

    Box::new(stack.get_blocking::<Controller>())
}
