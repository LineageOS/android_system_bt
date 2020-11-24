//! Bluetooth common library

/// Provides waking timer abstractions
pub mod time;

#[macro_use]
mod ready;


#[cfg(test)]
#[macro_use]
mod asserts;
