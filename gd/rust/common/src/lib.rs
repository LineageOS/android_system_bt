//! Bluetooth common library
#[macro_use]
extern crate lazy_static;

/// Provides waking timer abstractions
pub mod time;

#[macro_use]
mod ready;

#[cfg(test)]
#[macro_use]
mod asserts;

/// Provides runtime configured-at-startup flags
pub mod init_flags;

/// Provides runtime configured system properties. Stubbed for non-Android.
pub mod sys_prop;

/// Inits logging for Android
#[cfg(target_os = "android")]
pub fn init_logging() {
    android_logger::init_once(
        android_logger::Config::default().with_tag("bt").with_min_level(log::Level::Debug),
    );
}

/// Inits logging for host
#[cfg(not(target_os = "android"))]
pub fn init_logging() {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Debug)
        .parse_default_env()
        .try_init()
        .ok();
}

/// Indicates the object can be converted to a GRPC service
pub trait GrpcFacade {
    /// Convert the object into the service
    fn into_grpc(self) -> grpcio::Service;
}

/// Useful for distinguishing between BT classic & LE in functions that support both
#[derive(Debug, Clone, Copy)]
pub enum Bluetooth {
    /// Classic BT we all know and love, started in the 90s.
    Classic,
    /// Bluetooth low energy from the 2010s. Also known as BLE, BTLE, etc.
    Le,
}
