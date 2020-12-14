//! Loads info from the controller at startup

use crate::HciExports;
use bt_packets::hci::{
    Enable, ErrorCode, LeSetEventMaskBuilder, LocalVersionInformation, ReadBufferSizeBuilder,
    ReadLocalExtendedFeaturesBuilder, ReadLocalNameBuilder, ReadLocalSupportedCommandsBuilder,
    ReadLocalVersionInformationBuilder, SetEventMaskBuilder, WriteLeHostSupportBuilder,
    WriteSimplePairingModeBuilder,
};
use gddi::{module, provides, Stoppable};

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

    let supported_commands = assert_success!(hci.send(ReadLocalSupportedCommandsBuilder {}))
        .get_supported_commands()
        .clone();

    let lmp_features = read_lmp_features(&mut hci).await;

    let buffer_size = assert_success!(hci.send(ReadBufferSizeBuilder {}));

    ControllerExports {
        name,
        version_info,
        supported_commands,
        lmp_features,
        acl_buffer_length: buffer_size.get_acl_data_packet_length(),
        acl_buffers: buffer_size.get_total_num_acl_data_packets(),
        sco_buffer_length: buffer_size.get_synchronous_data_packet_length(),
        sco_buffers: buffer_size.get_total_num_synchronous_data_packets(),
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
    supported_commands: [u8; 64],
    lmp_features: Vec<u64>,
    acl_buffer_length: u16,
    acl_buffers: u16,
    sco_buffer_length: u8,
    sco_buffers: u16,
}
