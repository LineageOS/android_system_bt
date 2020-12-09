//! System properties on Android

#[cfg(target_os = "android")]
#[cxx::bridge(namespace = bluetooth::common::sys_prop)]
mod ffi {
    extern "C" {
        include!("src/ffi/sys_prop.h");
        fn get(name: &str) -> String;
    }
}

/// Gets the value of a system property on Android
#[cfg(target_os = "android")]
pub fn get(name: &str) -> Option<String> {
    let value = ffi::get(name);

    if !value.is_empty() {
        Some(value)
    } else {
        None
    }
}

/// Fake getter for non-Android, which will always return nothing.
/// Only added so it compiles & you can conditionally using cfg!
#[cfg(not(target_os = "android"))]
pub fn get(_name: &str) -> Option<String> {
    None
}
