//! Rust protobuf code for HCI layer facade service

/// Empty is needed by HciLayerFacadeService
/// Refer to the following on why we are doing this and for possible solutions:
/// https://github.com/tikv/grpc-rs/issues/276
pub mod empty {
    pub use protobuf::well_known_types::Empty;
}

pub use hci_layer_facade_proto::facade;
pub mod hci_layer_facade_grpc;
