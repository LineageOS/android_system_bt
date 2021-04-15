//! Merged bridge

pub use crate::controller::*;
pub use crate::hci::*;
pub use crate::stack::*;

#[cxx::bridge(namespace = bluetooth::shim::rust)]
pub mod ffi {
    extern "Rust" {
        type Stack;
        type Hci;
        type Controller;

        // Stack
        fn stack_create() -> Box<Stack>;
        fn stack_start(stack: &mut Stack);
        fn stack_stop(stack: &mut Stack);

        fn get_hci(stack: &mut Stack) -> Box<Hci>;
        fn get_controller(stack: &mut Stack) -> Box<Controller>;

        // HCI
        fn hci_set_acl_callback(hci: &mut Hci, callback: UniquePtr<u8SliceCallback>);
        fn hci_set_evt_callback(hci: &mut Hci, callback: UniquePtr<u8SliceCallback>);
        fn hci_set_le_evt_callback(hci: &mut Hci, callback: UniquePtr<u8SliceCallback>);

        fn hci_send_command(hci: &mut Hci, data: &[u8], callback: UniquePtr<u8SliceOnceCallback>);
        fn hci_send_acl(hci: &mut Hci, data: &[u8]);
        fn hci_register_event(hci: &mut Hci, event: u8);
        fn hci_register_le_event(hci: &mut Hci, subevent: u8);

        // Controller
        fn controller_supports_simple_pairing(c: &Controller) -> bool;
        fn controller_supports_secure_connections(c: &Controller) -> bool;
        fn controller_supports_simultaneous_le_bredr(c: &Controller) -> bool;
        fn controller_supports_interlaced_inquiry_scan(c: &Controller) -> bool;
        fn controller_supports_rssi_with_inquiry_results(c: &Controller) -> bool;
        fn controller_supports_extended_inquiry_response(c: &Controller) -> bool;
        fn controller_supports_role_switch(c: &Controller) -> bool;
        fn controller_supports_three_slot_packets(c: &Controller) -> bool;
        fn controller_supports_five_slot_packets(c: &Controller) -> bool;
        fn controller_supports_classic_2m_phy(c: &Controller) -> bool;
        fn controller_supports_classic_3m_phy(c: &Controller) -> bool;
        fn controller_supports_three_slot_edr_packets(c: &Controller) -> bool;
        fn controller_supports_five_slot_edr_packets(c: &Controller) -> bool;
        fn controller_supports_sco(c: &Controller) -> bool;
        fn controller_supports_hv2_packets(c: &Controller) -> bool;
        fn controller_supports_hv3_packets(c: &Controller) -> bool;
        fn controller_supports_ev3_packets(c: &Controller) -> bool;
        fn controller_supports_ev4_packets(c: &Controller) -> bool;
        fn controller_supports_ev5_packets(c: &Controller) -> bool;
        fn controller_supports_esco_2m_phy(c: &Controller) -> bool;
        fn controller_supports_esco_3m_phy(c: &Controller) -> bool;
        fn controller_supports_three_slot_esco_edr_packets(c: &Controller) -> bool;
        fn controller_supports_hold_mode(c: &Controller) -> bool;
        fn controller_supports_sniff_mode(c: &Controller) -> bool;
        fn controller_supports_park_mode(c: &Controller) -> bool;
        fn controller_supports_non_flushable_pb(c: &Controller) -> bool;
        fn controller_supports_sniff_subrating(c: &Controller) -> bool;
        fn controller_supports_encryption_pause(c: &Controller) -> bool;
        fn controller_supports_ble(c: &Controller) -> bool;

        fn controller_supports_privacy(c: &Controller) -> bool;
        fn controller_supports_packet_extension(c: &Controller) -> bool;
        fn controller_supports_connection_parameters_request(c: &Controller) -> bool;
        fn controller_supports_ble_2m_phy(c: &Controller) -> bool;
        fn controller_supports_ble_coded_phy(c: &Controller) -> bool;
        fn controller_supports_extended_advertising(c: &Controller) -> bool;
        fn controller_supports_periodic_advertising(c: &Controller) -> bool;
        fn controller_supports_peripheral_initiated_feature_exchange(c: &Controller) -> bool;
        fn controller_supports_connection_parameter_request(c: &Controller) -> bool;
        fn controller_supports_periodic_advertising_sync_transfer_sender(c: &Controller) -> bool;
        fn controller_supports_periodic_advertising_sync_transfer_recipient(c: &Controller)
            -> bool;
        fn controller_supports_connected_iso_stream_central(c: &Controller) -> bool;
        fn controller_supports_connected_iso_stream_peripheral(c: &Controller) -> bool;
        fn controller_supports_iso_broadcaster(c: &Controller) -> bool;
        fn controller_supports_synchronized_receiver(c: &Controller) -> bool;

        fn controller_supports_reading_remote_extended_features(c: &Controller) -> bool;
        fn controller_supports_enhanced_setup_synchronous_connection(c: &Controller) -> bool;
        fn controller_supports_enhanced_accept_synchronous_connection(c: &Controller) -> bool;
        fn controller_supports_ble_set_privacy_mode(c: &Controller) -> bool;

        fn controller_get_acl_buffer_length(c: &Controller) -> u16;
        fn controller_get_le_buffer_length(c: &Controller) -> u16;
        fn controller_get_iso_buffer_length(c: &Controller) -> u16;
        fn controller_get_le_suggested_default_data_length(c: &Controller) -> u16;
        fn controller_get_le_maximum_tx_data_length(c: &Controller) -> u16;
        fn controller_get_le_maximum_tx_time(c: &Controller) -> u16;
        fn controller_get_le_max_advertising_data_length(c: &Controller) -> u16;
        fn controller_get_le_supported_advertising_sets(c: &Controller) -> u8;
        fn controller_get_le_periodic_advertiser_list_size(c: &Controller) -> u8;
        fn controller_get_acl_buffers(c: &Controller) -> u16;
        fn controller_get_le_buffers(c: &Controller) -> u8;
        fn controller_get_iso_buffers(c: &Controller) -> u8;
        fn controller_get_le_connect_list_size(c: &Controller) -> u8;
        fn controller_get_le_resolving_list_size(c: &Controller) -> u8;
        fn controller_get_le_supported_states(c: &Controller) -> u64;

        fn controller_get_address(c: &Controller) -> String;
    }

    unsafe extern "C++" {
        include!("callbacks/callbacks.h");

        type u8SliceCallback;
        fn Run(self: &u8SliceCallback, data: &[u8]);

        type u8SliceOnceCallback;
        fn Run(self: &u8SliceOnceCallback, data: &[u8]);
    }
}
