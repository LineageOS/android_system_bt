//! Controller shim

use bt_hci::ControllerExports;
use bt_packets::hci::OpCode;
use paste::paste;
use std::sync::Arc;

#[cxx::bridge(namespace = bluetooth::shim::rust)]
mod ffi {
    extern "Rust" {
        type Controller;

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
}

pub type Controller = Arc<ControllerExports>;

macro_rules! feature_getters {
    ($($id:ident),*) => {
        paste! {
            $(
                fn [<controller_supports_ $id>](c: &Controller) -> bool {
                    c.features.$id
                }
            )*
        }
    }
}

feature_getters! {
    simple_pairing,
    secure_connections,
    simultaneous_le_bredr,
    interlaced_inquiry_scan,
    rssi_with_inquiry_results,
    extended_inquiry_response,
    role_switch,
    three_slot_packets,
    five_slot_packets,
    classic_2m_phy,
    classic_3m_phy,
    three_slot_edr_packets,
    five_slot_edr_packets,
    sco,
    hv2_packets,
    hv3_packets,
    ev3_packets,
    ev4_packets,
    ev5_packets,
    esco_2m_phy,
    esco_3m_phy,
    three_slot_esco_edr_packets,
    hold_mode,
    sniff_mode,
    park_mode,
    non_flushable_pb,
    sniff_subrating,
    encryption_pause,
    ble
}

macro_rules! le_feature_getters {
    ($($id:ident),*) => {
        paste! {
            $(
                fn [<controller_supports_ $id>](c: &Controller) -> bool {
                    c.le_features.$id
                }
            )*
        }
    }
}

le_feature_getters! {
    privacy,
    packet_extension,
    connection_parameters_request,
    ble_2m_phy,
    ble_coded_phy,
    extended_advertising,
    periodic_advertising,
    peripheral_initiated_feature_exchange,
    connection_parameter_request,
    periodic_advertising_sync_transfer_sender,
    periodic_advertising_sync_transfer_recipient,
    connected_iso_stream_central,
    connected_iso_stream_peripheral,
    iso_broadcaster,
    synchronized_receiver
}

macro_rules! opcode_getters {
    ($($id:ident => $opcode:path),*) => {
        paste! {
            $(
                fn [<controller_supports_ $id>](c: &Controller) -> bool {
                    c.commands.is_supported($opcode)
                }
            )*
        }
    }
}

opcode_getters! {
    reading_remote_extended_features => OpCode::ReadRemoteSupportedFeatures,
    enhanced_setup_synchronous_connection => OpCode::EnhancedSetupSynchronousConnection,
    enhanced_accept_synchronous_connection => OpCode::EnhancedAcceptSynchronousConnection,
    ble_set_privacy_mode => OpCode::LeSetPrivacyMode
}

macro_rules! field_getters {
    ($($id:ident : $type:ty),*) => {
        paste! {
            $(
                fn [<controller_get_ $id>](c: &Controller) -> $type {
                    c.$id
                }
            )*
        }
    }
}

field_getters! {
    acl_buffer_length: u16,
    le_buffer_length: u16,
    iso_buffer_length: u16,
    le_suggested_default_data_length: u16,
    le_max_advertising_data_length: u16,
    le_supported_advertising_sets: u8,
    le_periodic_advertiser_list_size: u8,
    acl_buffers: u16,
    le_buffers: u8,
    iso_buffers: u8,
    le_connect_list_size: u8,
    le_resolving_list_size: u8,
    le_supported_states: u64
}

fn controller_get_le_maximum_tx_data_length(c: &Controller) -> u16 {
    c.le_max_data_length.supported_max_tx_octets
}

fn controller_get_address(c: &Controller) -> String {
    c.address.to_string()
}
