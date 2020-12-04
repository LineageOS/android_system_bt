//! Bluetooth common library

/// Provides waking timer abstractions
pub mod time;

#[macro_use]
mod ready;

#[cfg(test)]
#[macro_use]
mod asserts;

mod init_flags;

/// Inits logging for Android
#[cfg(target_os = "android")]
pub fn init_logging() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("bt")
            .with_min_level(log::Level::Debug),
    );
}

/// Inits logging for host
#[cfg(not(target_os = "android"))]
pub fn init_logging() {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Debug)
        .parse_default_env()
        .init();
}
