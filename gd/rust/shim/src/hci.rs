//! Hci shim

#[cxx::bridge(namespace = bluetooth::shim::rust)]
mod ffi {
    extern "C" {
        include!("callbacks/callbacks.h");

        type u8SliceCallback;

        fn Run(&self, data: &[u8]);
    }

    extern "Rust" {
        fn hci_set_acl_callback(callback: UniquePtr<u8SliceCallback>);
        fn hci_send_command(data: &[u8]);
        fn hci_send_acl(data: &[u8]);
        fn hci_register_event(event: u8, callback: UniquePtr<u8SliceCallback>);
        fn hci_register_le_event(subevent: u8, callback: UniquePtr<u8SliceCallback>);
    }
}

fn hci_send_command(_data: &[u8]) {
}

fn hci_send_acl(_data: &[u8]) {
}

fn hci_register_event(_event: u8, _callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
}

fn hci_register_le_event(_subevent: u8, _callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
}

fn hci_set_acl_callback(_callback: cxx::UniquePtr<ffi::u8SliceCallback>) {
}
