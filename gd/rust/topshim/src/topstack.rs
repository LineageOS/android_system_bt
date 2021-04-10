//! Stack on top of the Bluetooth interface shim
//!
//! Helpers for dealing with the stack on top of the Bluetooth interface.

use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

lazy_static! {
    // Shared runtime for topshim handlers. All async tasks will get run by this
    // runtime and this will properly serialize all spawned tasks.
    pub static ref RUNTIME: Arc<Runtime> = Arc::new(
        Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap()
    );
}

pub fn get_runtime() -> Arc<Runtime> {
    RUNTIME.clone()
}
