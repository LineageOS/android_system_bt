//! Loads info from the controller at startup

use crate::{Address, HciExports};
use bt_packets::hci::{
    Enable, ErrorCode, LeMaximumDataLength, LeReadBufferSizeV1Builder, LeReadBufferSizeV2Builder,
    LeReadConnectListSizeBuilder, LeReadLocalSupportedFeaturesBuilder,
    LeReadMaximumAdvertisingDataLengthBuilder, LeReadMaximumDataLengthBuilder,
    LeReadNumberOfSupportedAdvertisingSetsBuilder, LeReadPeriodicAdvertiserListSizeBuilder,
    LeReadResolvingListSizeBuilder, LeReadSuggestedDefaultDataLengthBuilder,
    LeReadSupportedStatesBuilder, LeSetEventMaskBuilder, LocalVersionInformation, OpCode,
    OpCodeIndex, ReadBdAddrBuilder, ReadBufferSizeBuilder, ReadLocalExtendedFeaturesBuilder,
    ReadLocalNameBuilder, ReadLocalSupportedCommandsBuilder, ReadLocalVersionInformationBuilder,
    SetEventMaskBuilder, WriteLeHostSupportBuilder, WriteSimplePairingModeBuilder,
};
use gddi::{module, provides, Stoppable};
use num_traits::ToPrimitive;
use std::convert::TryFrom;

module! {
    controller_module,
    providers {
        ControllerExports => provide_controller,
    },
}

macro_rules! assert_success {
    ($hci:ident.send($builder:expr)) => {{
        let response = $hci.send($builder).await;
        assert!(response.get_status() == ErrorCode::Success);

        response
    }};
}

#[provides]
async fn provide_controller(mut hci: HciExports) -> ControllerExports {
    assert_success!(hci.send(LeSetEventMaskBuilder { le_event_mask: 0x0000000000021e7f }));
    assert_success!(hci.send(SetEventMaskBuilder { event_mask: 0x3dbfffffffffffff }));
    assert_success!(
        hci.send(WriteSimplePairingModeBuilder { simple_pairing_mode: Enable::Enabled })
    );
    assert_success!(hci.send(WriteLeHostSupportBuilder { le_supported_host: Enable::Enabled }));

    let name = null_terminated_to_string(
        assert_success!(hci.send(ReadLocalNameBuilder {})).get_local_name(),
    );

    let version_info = assert_success!(hci.send(ReadLocalVersionInformationBuilder {}))
        .get_local_version_information()
        .clone();

    let commands = SupportedCommands {
        supported: *assert_success!(hci.send(ReadLocalSupportedCommandsBuilder {}))
            .get_supported_commands(),
    };

    let lmp_features = read_lmp_features(&mut hci).await;

    let buffer_size = assert_success!(hci.send(ReadBufferSizeBuilder {}));
    let acl_buffer_length = buffer_size.get_acl_data_packet_length();
    let mut acl_buffers = buffer_size.get_total_num_acl_data_packets();

    let (mut le_buffer_length, mut le_buffers, iso_buffer_length, iso_buffers) =
        if commands.is_supported(OpCode::LeReadBufferSizeV2) {
            let response = assert_success!(hci.send(LeReadBufferSizeV2Builder {}));
            (
                response.get_le_buffer_size().le_data_packet_length,
                response.get_le_buffer_size().total_num_le_packets,
                response.get_iso_buffer_size().le_data_packet_length,
                response.get_iso_buffer_size().total_num_le_packets,
            )
        } else {
            let response = assert_success!(hci.send(LeReadBufferSizeV1Builder {}));
            (
                response.get_le_buffer_size().le_data_packet_length,
                response.get_le_buffer_size().total_num_le_packets,
                0,
                0,
            )
        };

    // If the controller reports zero LE buffers, the ACL buffers are shared between classic & LE
    if le_buffers == 0 {
        le_buffers = (acl_buffers / 2) as u8;
        acl_buffers -= le_buffers as u16;
        le_buffer_length = acl_buffer_length;
    }

    let le_features =
        assert_success!(hci.send(LeReadLocalSupportedFeaturesBuilder {})).get_le_features();
    let le_supported_states =
        assert_success!(hci.send(LeReadSupportedStatesBuilder {})).get_le_states();
    let le_connect_list_size =
        assert_success!(hci.send(LeReadConnectListSizeBuilder {})).get_connect_list_size();
    let le_resolving_list_size =
        assert_success!(hci.send(LeReadResolvingListSizeBuilder {})).get_resolving_list_size();

    let le_max_data_length = if commands.is_supported(OpCode::LeReadMaximumDataLength) {
        assert_success!(hci.send(LeReadMaximumDataLengthBuilder {}))
            .get_le_maximum_data_length()
            .clone()
    } else {
        LeMaximumDataLength {
            supported_max_rx_octets: 0,
            supported_max_rx_time: 0,
            supported_max_tx_octets: 0,
            supported_max_tx_time: 0,
        }
    };

    let le_suggested_default_data_length =
        if commands.is_supported(OpCode::LeReadSuggestedDefaultDataLength) {
            assert_success!(hci.send(LeReadSuggestedDefaultDataLengthBuilder {})).get_tx_octets()
        } else {
            0
        };

    let le_max_advertising_data_length =
        if commands.is_supported(OpCode::LeReadMaximumAdvertisingDataLength) {
            assert_success!(hci.send(LeReadMaximumAdvertisingDataLengthBuilder {}))
                .get_maximum_advertising_data_length()
        } else {
            31
        };
    let le_supported_advertising_sets =
        if commands.is_supported(OpCode::LeReadNumberOfSupportedAdvertisingSets) {
            assert_success!(hci.send(LeReadNumberOfSupportedAdvertisingSetsBuilder {}))
                .get_number_supported_advertising_sets()
        } else {
            1
        };
    let le_periodic_advertiser_list_size =
        if commands.is_supported(OpCode::LeReadPeriodicAdvertisingListSize) {
            assert_success!(hci.send(LeReadPeriodicAdvertiserListSizeBuilder {}))
                .get_periodic_advertiser_list_size()
        } else {
            0
        };

    let address = assert_success!(hci.send(ReadBdAddrBuilder {})).get_bd_addr();

    ControllerExports {
        name,
        address,
        version_info,
        commands,
        lmp_features,
        acl_buffer_length,
        acl_buffers,
        sco_buffer_length: buffer_size.get_synchronous_data_packet_length(),
        sco_buffers: buffer_size.get_total_num_synchronous_data_packets(),
        le_buffer_length,
        le_buffers,
        iso_buffer_length,
        iso_buffers,
        le_features,
        le_supported_states,
        le_connect_list_size,
        le_resolving_list_size,
        le_max_data_length,
        le_suggested_default_data_length,
        le_max_advertising_data_length,
        le_supported_advertising_sets,
        le_periodic_advertiser_list_size,
    }
}

async fn read_lmp_features(hci: &mut HciExports) -> Vec<u64> {
    let mut features = Vec::new();
    let mut page_number: u8 = 0;
    let mut max_page_number: u8 = 1;
    while page_number < max_page_number {
        let response = assert_success!(hci.send(ReadLocalExtendedFeaturesBuilder { page_number }));
        max_page_number = response.get_maximum_page_number();
        features.push(response.get_extended_lmp_features());
        page_number += 1;
    }

    features
}

/// Controller interface
#[derive(Clone, Stoppable)]
pub struct ControllerExports {
    name: String,
    address: Address,
    version_info: LocalVersionInformation,
    commands: SupportedCommands,
    lmp_features: Vec<u64>,
    acl_buffer_length: u16,
    acl_buffers: u16,
    sco_buffer_length: u8,
    sco_buffers: u16,
    le_buffer_length: u16,
    le_buffers: u8,
    iso_buffer_length: u16,
    iso_buffers: u8,
    le_features: u64,
    le_supported_states: u64,
    le_connect_list_size: u8,
    le_resolving_list_size: u8,
    le_max_data_length: LeMaximumDataLength,
    le_suggested_default_data_length: u16,
    le_max_advertising_data_length: u16,
    le_supported_advertising_sets: u8,
    le_periodic_advertiser_list_size: u8,
}

/// Convenience struct for checking what commands are supported
#[derive(Clone)]
pub struct SupportedCommands {
    supported: [u8; 64],
}

impl SupportedCommands {
    /// Check whether a given opcode is supported by the controller
    pub fn is_supported(&self, opcode: OpCode) -> bool {
        match opcode {
            OpCode::ReadLocalSupportedCommands | OpCode::CreateNewUnitKey => true,
            _ => {
                let converted = OpCodeIndex::try_from(opcode);
                if converted.is_err() {
                    return false;
                }

                let index = converted.unwrap().to_usize().unwrap();

                // The 10 here looks sus, but hci_packets.pdl mentions the index value
                // is octet * 10 + bit
                self.supported[index / 10] & (1 << (index % 10)) == 1
            }
        }
    }
}

fn null_terminated_to_string(slice: &[u8]) -> String {
    let temp = std::str::from_utf8(slice).unwrap();
    temp[0..temp.find('\0').unwrap()].to_string()
}
