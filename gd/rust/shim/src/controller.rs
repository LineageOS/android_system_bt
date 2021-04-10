//! Controller shim

use bt_hci::ControllerExports;
use bt_packets::hci::OpCode;
use paste::paste;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone)]
pub struct Controller(pub Arc<ControllerExports>);
impl Deref for Controller {
    type Target = Arc<ControllerExports>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

macro_rules! feature_getters {
    ($($id:ident),*) => {
        paste! {
            $(
                pub fn [<controller_supports_ $id>](c: &Controller) -> bool {
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
                pub fn [<controller_supports_ $id>](c: &Controller) -> bool {
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
                pub fn [<controller_supports_ $id>](c: &Controller) -> bool {
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
                pub fn [<controller_get_ $id>](c: &Controller) -> $type {
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

pub fn controller_get_le_maximum_tx_data_length(c: &Controller) -> u16 {
    c.le_max_data_length.supported_max_tx_octets
}

pub fn controller_get_address(c: &Controller) -> String {
    c.address.to_string()
}
