//! Stack management

#[cxx::bridge(namespace = bluetooth::rust::stack)]
mod ffi {
    extern "Rust" {
        fn start();
        fn stop();
    }
}

pub fn start() {
}

pub fn stop() {
}
