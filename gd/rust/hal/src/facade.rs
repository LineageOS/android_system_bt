//! BT HCI HAL facade


use bt_hal_proto::facade_grpc::{create_hci_hal_facade, HciHalFacade};
use bt_hal_proto::facade::*;
use bt_hal_proto::empty::Empty;

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
    fn send_hci_command(
        &mut self,
        _ctx: RpcContext<'_>,
        _cmd: HciCommandPacket,
        _sink: UnarySink<Empty>,
    ) {
        unimplemented!()
    }

    fn send_hci_acl(&mut self, _ctx: RpcContext<'_>, _acl: HciAclPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn send_hci_sco(&mut self, _ctx: RpcContext<'_>, _sco: HciScoPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn send_hci_iso(&mut self, _ctx: RpcContext<'_>, _iso: HciIsoPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn fetch_hci_event(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        _sink: ServerStreamingSink<HciEventPacket>,
    ) {
        unimplemented!()
    }

    fn fetch_hci_acl(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        _sink: ServerStreamingSink<HciAclPacket>,
    ) {
        unimplemented!()
    }

    fn fetch_hci_sco(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        _sink: ServerStreamingSink<HciScoPacket>,
    ) {
        unimplemented!()
    }

    fn fetch_hci_iso(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        _sink: ServerStreamingSink<HciIsoPacket>,
    ) {
        unimplemented!()
    }
}
