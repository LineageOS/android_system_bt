//! reimport of generated packets (to go away once rust_genrule exists)

#![allow(clippy::all)]
#![allow(unused)]
#![allow(missing_docs)]

pub mod hci {
    use bt_hci_custom_types::*;

    include!(concat!(env!("OUT_DIR"), "/hci_packets.rs"));
}
