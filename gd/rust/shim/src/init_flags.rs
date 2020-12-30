#[cxx::bridge(namespace = bluetooth::common::init_flags)]
mod ffi {
    extern "Rust" {
        fn load(flags: Vec<String>);
        fn set_all_for_testing();

        fn gd_core_is_enabled() -> bool;
        fn gd_security_is_enabled() -> bool;
        fn gd_advertising_is_enabled() -> bool;
        fn gd_scanning_is_enabled() -> bool;
        fn gd_acl_is_enabled() -> bool;
        fn gd_l2cap_is_enabled() -> bool;
        fn gd_hci_is_enabled() -> bool;
        fn gd_controller_is_enabled() -> bool;
        fn gatt_robust_caching_is_enabled() -> bool;
        fn btaa_hci_is_enabled() -> bool;
        fn gd_rust_is_enabled() -> bool;
    }
}

use bt_common::init_flags::*;
