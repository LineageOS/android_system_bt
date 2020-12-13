//! Loads info from the controller at startup

use crate::HciExports;
use bt_packets::hci::{
    Enable, ErrorCode, LeSetEventMaskBuilder, SetEventMaskBuilder, WriteSimplePairingModeBuilder, WriteLeHostSupportBuilder
};
use gddi::{module, provides, Stoppable};

module! {
    controller_module,
    providers {
        ControllerExports => provide_controller,
    },
}

macro_rules! assert_success {
    ($hci:ident.send($builder:expr)) => {
        assert!($hci.send($builder.build()).await.get_status() == ErrorCode::Success);
    };
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

    ControllerExports {}
}

/// Controller interface
#[derive(Clone, Stoppable)]
pub struct ControllerExports {}
