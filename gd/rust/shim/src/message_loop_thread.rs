//! Shim out the main thread in the BT stack, to reduce threading dances at the shim boundary

use bt_common::init_flags;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

#[cxx::bridge(namespace = bluetooth::shim::rust)]
mod ffi {
    unsafe extern "C++" {
        include!("callbacks/callbacks.h");

        type OnceClosure;
        fn Run(&self);
    }

    extern "Rust" {
        type MessageLoopThread;

        fn main_message_loop_thread_create() -> Box<MessageLoopThread>;
        fn main_message_loop_thread_start(thread: &mut MessageLoopThread) -> i32;
        fn main_message_loop_thread_do_delayed(
            thread: &mut MessageLoopThread,
            closure: UniquePtr<OnceClosure>,
            delay_ms: i64,
        );
    }
}

unsafe impl Send for ffi::OnceClosure {}

pub struct MessageLoopThread {
    rt: Arc<Runtime>,
    tx: UnboundedSender<cxx::UniquePtr<ffi::OnceClosure>>,
}

pub fn main_message_loop_thread_create() -> Box<MessageLoopThread> {
    assert!(init_flags::gd_rust_is_enabled());

    let rt = crate::stack::RUNTIME.clone();
    let (tx, mut rx) = unbounded_channel::<cxx::UniquePtr<ffi::OnceClosure>>();
    rt.spawn(async move {
        while let Some(c) = rx.recv().await {
            c.Run();
        }
    });

    Box::new(MessageLoopThread { rt, tx })
}

pub fn main_message_loop_thread_start(thread: &mut MessageLoopThread) -> i32 {
    assert!(init_flags::gd_rust_is_enabled());

    thread.rt.block_on(async move { nix::unistd::gettid().as_raw() })
}

pub fn main_message_loop_thread_do_delayed(
    thread: &mut MessageLoopThread,
    closure: cxx::UniquePtr<ffi::OnceClosure>,
    delay_ms: i64,
) {
    assert!(init_flags::gd_rust_is_enabled());
    if delay_ms == 0 {
        if thread.tx.send(closure).is_err() {
            log::error!("could not post task - shutting down?");
        }
    } else {
        thread.rt.spawn(async move {
            // NOTE: tokio's sleep can't wake up the system...
            // but hey, neither could the message loop from libchrome.
            //
            // ...and this way we don't use timerfds arbitrarily.
            //
            // #yolo
            tokio::time::sleep(Duration::from_millis(delay_ms.try_into().unwrap_or(0))).await;
            closure.Run();
        });
    }
}
