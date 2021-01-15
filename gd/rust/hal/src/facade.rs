//! BT HCI HAL facade

use crate::{AclHal, ControlHal};
use bt_common::GrpcFacade;
use bt_facade_helpers::RxAdapter;
use bt_facade_proto::common::Data;
use bt_facade_proto::empty::Empty;
use bt_facade_proto::hal_facade_grpc::{create_hci_hal_facade, HciHalFacade};
use bt_packets::hci::{AclPacket, CommandPacket, EventPacket};
use gddi::{module, provides, Stoppable};
use grpcio::*;

module! {
    hal_facade_module,
    providers {
        HciHalFacadeService => provide_facade,
    }
}

#[provides]
async fn provide_facade(control: ControlHal, acl: AclHal) -> HciHalFacadeService {
    HciHalFacadeService {
        evt_rx: RxAdapter::from_arc(control.rx.clone()),
        acl_rx: RxAdapter::from_arc(acl.rx.clone()),
        control,
        acl,
    }
}

/// HCI HAL facade service
#[derive(Clone, Stoppable)]
pub struct HciHalFacadeService {
    evt_rx: RxAdapter<EventPacket>,
    acl_rx: RxAdapter<AclPacket>,
    control: ControlHal,
    acl: AclHal,
}

impl GrpcFacade for HciHalFacadeService {
    fn into_grpc(self) -> grpcio::Service {
        create_hci_hal_facade(self)
    }
}

impl HciHalFacade for HciHalFacadeService {
    fn send_command(&mut self, ctx: RpcContext<'_>, mut data: Data, sink: UnarySink<Empty>) {
        let cmd_tx = self.control.tx.clone();
        ctx.spawn(async move {
            cmd_tx.send(CommandPacket::parse(&data.take_payload()).unwrap()).await.unwrap();
            sink.success(Empty::default()).await.unwrap();
        });
    }

    fn send_acl(&mut self, ctx: RpcContext<'_>, mut data: Data, sink: UnarySink<Empty>) {
        let acl_tx = self.acl.tx.clone();
        ctx.spawn(async move {
            acl_tx.send(AclPacket::parse(&data.take_payload()).unwrap()).await.unwrap();
            sink.success(Empty::default()).await.unwrap();
        });
    }

    fn send_sco(&mut self, _ctx: RpcContext<'_>, _sco: Data, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn send_iso(&mut self, _ctx: RpcContext<'_>, _iso: Data, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn stream_events(&mut self, ctx: RpcContext<'_>, _: Empty, sink: ServerStreamingSink<Data>) {
        self.evt_rx.stream_grpc(ctx, sink);
    }

    fn stream_acl(&mut self, ctx: RpcContext<'_>, _: Empty, sink: ServerStreamingSink<Data>) {
        self.acl_rx.stream_grpc(ctx, sink);
    }

    fn stream_sco(&mut self, _ctx: RpcContext<'_>, _: Empty, _sink: ServerStreamingSink<Data>) {
        unimplemented!()
    }

    fn stream_iso(&mut self, _ctx: RpcContext<'_>, _: Empty, _sink: ServerStreamingSink<Data>) {
        unimplemented!()
    }
}
