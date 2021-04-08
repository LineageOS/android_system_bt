//! Stack management

use crate::controller::Controller;
use crate::hci::Hci;
use bt_common::init_flags;
use bt_hci::ControllerExports;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

pub struct Stack(bt_main::Stack);

impl Deref for Stack {
    type Target = bt_main::Stack;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Stack {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

lazy_static! {
    pub static ref RUNTIME: Arc<Runtime> = Arc::new(
        Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap()
    );
}

pub fn stack_create() -> Box<Stack> {
    assert!(init_flags::gd_rust_is_enabled());

    let local_rt = RUNTIME.clone();
    RUNTIME.block_on(async move {
        let stack = bt_main::Stack::new(local_rt).await;
        stack.use_default_snoop().await;

        Box::new(Stack(stack))
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

    Box::new(Controller(stack.get_blocking::<Arc<ControllerExports>>()))
}
