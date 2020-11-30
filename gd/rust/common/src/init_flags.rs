use log::error;

#[cxx::bridge(namespace = bluetooth::common)]
mod ffi {
    extern "Rust" {
        fn init_flags_load(flags: Vec<String>);
    }
}

fn init_flags_load(flags: Vec<String>) {
    crate::init_logging();

    for flag in flags {
        error!("hello from rust: {}", flag);
    }
}
