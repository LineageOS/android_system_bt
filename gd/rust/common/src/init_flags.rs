use log::{error, info};
use paste::paste;
use std::sync::Mutex;

macro_rules! init_flags {
    (flags: { $($flag:ident),* }, dependencies: { $($parent:ident => $child:ident),* }) => {
        #[derive(Default)]
        struct InitFlags {
            $($flag: bool,)*
        }

        /// Sets all flags to true, for testing
        pub fn set_all_for_testing() {
            *FLAGS.lock().unwrap() = InitFlags { $($flag: true,)* };
        }

        impl InitFlags {
            fn parse(flags: Vec<String>) -> Self {
                $(let mut $flag = false;)*

                for flag in flags {
                    let values: Vec<&str> = flag.split("=").collect();
                    if values.len() != 2 {
                        error!("Bad flag {}, must be in <FLAG>=<VALUE> format", flag);
                        continue;
                    }

                    match values[0] {
                        $(concat!("INIT_", stringify!($flag)) => $flag = values[1].parse().unwrap_or(false),)*
                        _ => {}
                    }
                }

                Self { $($flag,)* }.reconcile()
            }

            fn reconcile(mut self) -> Self {
                // Loop to ensure dependencies can be specified in any order
                loop {
                    let mut any_change = false;
                    $(if self.$parent && !self.$child {
                        self.$child = true;
                        any_change = true;
                    })*

                    if !any_change {
                        break;
                    }
                }

                // TODO: acl should not be off if l2cap is on, but need to reconcile legacy code
                if self.gd_l2cap {
                    self.gd_acl = false;
                    self.gd_hci = true;
                }

                self
            }

            fn log(&self) {
                info!(concat!("Flags loaded: ", $(stringify!($flag), "={} ",)*), $(self.$flag,)*);
            }
        }

        paste! {
            $(
                #[allow(missing_docs)]
                pub fn [<$flag _is_enabled>]() -> bool {
                    FLAGS.lock().unwrap().$flag
                }
            )*
        }
    };
}

init_flags!(
    flags: {
        gd_core,
        gd_advertising,
        gd_scanning,
        gd_security,
        gd_acl,
        gd_l2cap,
        gd_hci,
        gd_controller,
        gatt_robust_caching,
        btaa_hci,
        gd_rust,
        gd_link_policy
    },
    dependencies: {
        gd_core => gd_security,
        gd_security => gd_acl,
        gd_acl => gd_controller,
        gd_controller => gd_hci,
        gd_link_policy => gd_acl
    }
);

lazy_static! {
    static ref FLAGS: Mutex<InitFlags> = Mutex::new(InitFlags::default());
}

/// Loads the flag values from the passed-in vector of string values
pub fn load(flags: Vec<String>) {
    crate::init_logging();

    let flags = InitFlags::parse(flags);
    flags.log();
    *FLAGS.lock().unwrap() = flags;
}
