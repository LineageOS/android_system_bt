//! The main entry point for the legacy C++ code
#[macro_use]
extern crate lazy_static;

mod bridge;
mod controller;
mod hci;
mod init_flags;
mod message_loop_thread;
mod stack;
