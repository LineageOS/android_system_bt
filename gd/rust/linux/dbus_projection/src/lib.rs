//! This crate provides tools to automatically project generic API to D-Bus RPC.
//!
//! For D-Bus projection to work automatically, the API needs to follow certain restrictions.

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus::nonblock::SyncConnection;
use dbus::strings::BusName;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A D-Bus "NameOwnerChanged" handler that continuously monitors client disconnects.
pub struct DisconnectWatcher {
    callbacks: Arc<Mutex<HashMap<BusName<'static>, Vec<Box<dyn Fn() + Send>>>>>,
}

impl DisconnectWatcher {
    /// Creates a new DisconnectWatcher with empty callbacks.
    pub fn new() -> DisconnectWatcher {
        DisconnectWatcher { callbacks: Arc::new(Mutex::new(HashMap::new())) }
    }
}

impl DisconnectWatcher {
    /// Adds a client address to be monitored for disconnect events.
    pub fn add(&mut self, address: BusName<'static>, callback: Box<dyn Fn() + Send>) {
        if !self.callbacks.lock().unwrap().contains_key(&address) {
            self.callbacks.lock().unwrap().insert(address.clone(), vec![]);
        }

        (*self.callbacks.lock().unwrap().get_mut(&address).unwrap()).push(callback);
    }

    /// Sets up the D-Bus handler that monitors client disconnects.
    pub async fn setup_watch(&mut self, conn: Arc<SyncConnection>) {
        let mr = MatchRule::new_signal("org.freedesktop.DBus", "NameOwnerChanged");

        conn.add_match_no_cb(&mr.match_str()).await.unwrap();
        let callbacks_map = self.callbacks.clone();
        conn.start_receive(
            mr,
            Box::new(move |msg, _conn| {
                // The args are "address", "old address", "new address".
                // https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-name-owner-changed
                let (addr, old, new) = msg.get3::<String, String, String>();

                if addr.is_none() || old.is_none() || new.is_none() {
                    return true;
                }

                if old.unwrap().eq("") || !new.unwrap().eq("") {
                    return true;
                }

                // If old address exists but new address is empty, that means that client is
                // disconnected. So call the registered callbacks to be notified of this client
                // disconnect.
                let addr = BusName::new(addr.unwrap()).unwrap().into_static();
                if !callbacks_map.lock().unwrap().contains_key(&addr) {
                    return true;
                }

                for callback in &callbacks_map.lock().unwrap()[&addr] {
                    callback();
                }

                callbacks_map.lock().unwrap().remove(&addr);

                true
            }),
        );
    }
}

#[macro_export]
macro_rules! impl_dbus_arg_enum {
    ($enum_type:ty) => {
        impl DBusArg for $enum_type {
            type DBusType = i32;
            fn from_dbus(
                data: i32,
                _conn: Arc<SyncConnection>,
                _remote: BusName<'static>,
                _disconnect_watcher: Arc<Mutex<dbus_projection::DisconnectWatcher>>,
            ) -> Result<$enum_type, Box<dyn Error>> {
                match <$enum_type>::from_i32(data) {
                    Some(x) => Ok(x),
                    None => Err(Box::new(DBusArgError::new(String::from(format!(
                        "error converting {} to {}",
                        data,
                        stringify!($enum_type)
                    ))))),
                }
            }

            fn to_dbus(data: $enum_type) -> Result<i32, Box<dyn Error>> {
                return Ok(data.to_i32().unwrap());
            }
        }
    };
}
