//! Loads info from the controller at startup

use crate::HciExports;
use bt_packets::hci::{
    Enable, ErrorCode, LeReadBufferSizeV1Builder, LeReadBufferSizeV2Builder, LeSetEventMaskBuilder,
    LocalVersionInformation, OpCode, OpCodeIndex, ReadBufferSizeBuilder,
    ReadLocalExtendedFeaturesBuilder, ReadLocalNameBuilder, ReadLocalSupportedCommandsBuilder,
    ReadLocalVersionInformationBuilder, SetEventMaskBuilder, WriteLeHostSupportBuilder,
    WriteSimplePairingModeBuilder,
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
    assert_success!(hci.send(LeSetEventMaskBuilder {
        le_event_mask: 0x0000000000021e7f
    }));
    assert_success!(hci.send(SetEventMaskBuilder {
        event_mask: 0x3dbfffffffffffff
    }));
    assert_success!(hci.send(WriteSimplePairingModeBuilder {
        simple_pairing_mode: Enable::Enabled
    }));
    assert_success!(hci.send(WriteLeHostSupportBuilder {
        le_supported_host: Enable::Enabled
    }));

    let response = assert_success!(hci.send(ReadLocalNameBuilder {}));
    let name = std::str::from_utf8(response.get_local_name()).unwrap();
    let name = name[0..name.find('\0').unwrap()].to_string();

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

    let mut le_buffer_length;
    let mut le_buffers;
    let mut iso_buffer_length = 0;
    let mut iso_buffers = 0;
    if commands.is_supported(OpCode::LeReadBufferSizeV2) {
        let response = assert_success!(hci.send(LeReadBufferSizeV2Builder {}));
        le_buffer_length = response.get_le_buffer_size().le_data_packet_length;
        le_buffers = response.get_le_buffer_size().total_num_le_packets;
        iso_buffer_length = response.get_iso_buffer_size().le_data_packet_length;
        iso_buffers = response.get_iso_buffer_size().total_num_le_packets;
    } else {
        let response = assert_success!(hci.send(LeReadBufferSizeV1Builder {}));
        le_buffer_length = response.get_le_buffer_size().le_data_packet_length;
        le_buffers = response.get_le_buffer_size().total_num_le_packets;
    }

    // If the controller reports zero LE buffers, the ACL buffers are shared between classic & LE
    if le_buffers == 0 {
        le_buffers = (acl_buffers / 2) as u8;
        acl_buffers -= le_buffers as u16;
        le_buffer_length = acl_buffer_length;
    }

    ControllerExports {
        name,
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
