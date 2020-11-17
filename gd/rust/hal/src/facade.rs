//! BT HCI HAL facade

use bt_hal_proto::empty::Empty;
use bt_hal_proto::facade::*;
use bt_hal_proto::facade_grpc::{create_hci_hal_facade, HciHalFacade};

use tokio::runtime::Runtime;

use grpcio::*;

use std::sync::Arc;

/// HCI HAL facade service
#[derive(Clone)]
pub struct HciHalFacadeService {
    rt: Arc<Runtime>,
}

impl HciHalFacadeService {
    /// Create a new instance of HCI HAL facade service
    pub fn create(rt: Arc<Runtime>) -> grpcio::Service {
        create_hci_hal_facade(Self { rt })
    }
}

impl HciHalFacade for HciHalFacadeService {
    fn send_command(&mut self, _ctx: RpcContext<'_>, _cmd: Command, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn send_acl(&mut self, _ctx: RpcContext<'_>, _acl: AclPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn send_sco(&mut self, _ctx: RpcContext<'_>, _sco: ScoPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn send_iso(&mut self, _ctx: RpcContext<'_>, _iso: IsoPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn stream_events(&mut self, _ctx: RpcContext<'_>, _: Empty, _sink: ServerStreamingSink<Event>) {
        unimplemented!()
    }

    fn stream_acl(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        _sink: ServerStreamingSink<AclPacket>,
    ) {
        unimplemented!()
    }

    fn stream_sco(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        _sink: ServerStreamingSink<ScoPacket>,
    ) {
        unimplemented!()
    }

    fn stream_iso(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        _sink: ServerStreamingSink<IsoPacket>,
    ) {
        unimplemented!()
    }
}
