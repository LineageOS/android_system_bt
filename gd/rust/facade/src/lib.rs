//! Bluetooth testing root facade service

mod rootservice_grpc;

/// Refer to the following on why we are doing this and for possible solutions:
/// https://github.com/tikv/grpc-rs/issues/276
pub mod empty {
    pub use protobuf::well_known_types::Empty;
}

pub use bt_facade_rootservice_proto::rootservice;
pub use bt_facade_common_proto::common;

use tokio::runtime::Runtime;

use grpcio::*;

use std::sync::Arc;

/// Bluetooth testing root facade service
#[derive(Clone)]
pub struct RootFacadeService {
    /// Tokio runtime
    pub rt: Arc<Runtime>,
}

use bt_facade_rootservice_proto::rootservice::*;
use rootservice_grpc::create_root_facade;
use rootservice_grpc::RootFacade;

impl RootFacadeService {
    /// Create a new instance of the root facade service
    pub fn create(rt: Arc<Runtime>) -> grpcio::Service {
        create_root_facade(Self { rt })
    }
}

impl RootFacade for RootFacadeService {
    fn start_stack(
        &mut self,
        _ctx: RpcContext<'_>,
        mut _cmd: StartStackRequest,
        _sink: UnarySink<StartStackResponse>,
    ) {
        unimplemented!()
    }

    fn stop_stack(
        &mut self,
        _ctx: RpcContext<'_>,
        mut _cmd: StopStackRequest,
        _sink: UnarySink<StopStackResponse>,
    ) {
        unimplemented!()
    }
}
