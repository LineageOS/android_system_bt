//! HCI layer facade

use crate::HciExports;
use bt_common::GrpcFacade;
use bt_facade_proto::empty::Empty;
use bt_facade_proto::hci_facade::*;
use bt_facade_proto::hci_facade_grpc::{create_hci_layer_facade, HciLayerFacade};
use bt_packet::HciEvent;
use futures::sink::SinkExt;
use gddi::{module, provides, Stoppable};
use grpcio::*;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Mutex;

module! {
    facade_module,
    providers {
        HciLayerFacadeService => provide_facade,
    }
}

#[provides]
async fn provide_facade(hci_exports: HciExports, rt: Arc<Runtime>) -> HciLayerFacadeService {
    let (from_hci_evt_tx, to_grpc_evt_rx) = channel::<HciEvent>(10);
    HciLayerFacadeService {
        hci_exports,
        rt,
        from_hci_evt_tx,
        to_grpc_evt_rx: Arc::new(Mutex::new(to_grpc_evt_rx)),
    }
}

/// HCI layer facade service
#[derive(Clone, Stoppable)]
pub struct HciLayerFacadeService {
    hci_exports: HciExports,
    rt: Arc<Runtime>,
    from_hci_evt_tx: Sender<HciEvent>,
    to_grpc_evt_rx: Arc<Mutex<Receiver<HciEvent>>>,
}

impl GrpcFacade for HciLayerFacadeService {
    fn into_grpc(self) -> grpcio::Service {
        create_hci_layer_facade(self)
    }
}

impl HciLayerFacade for HciLayerFacadeService {
    fn send_command_with_complete(
        &mut self,
        _ctx: RpcContext<'_>,
        mut cmd: Command,
        sink: UnarySink<Empty>,
    ) {
        self.rt.block_on(self.hci_exports.enqueue_command_with_complete(cmd.take_payload().into()));
        sink.success(Empty::default());
    }

    fn send_command_with_status(
        &mut self,
        _ctx: RpcContext<'_>,
        mut cmd: Command,
        sink: UnarySink<Empty>,
    ) {
        self.rt.block_on(self.hci_exports.enqueue_command_with_complete(cmd.take_payload().into()));
        sink.success(Empty::default());
    }

    fn request_event(&mut self, _ctx: RpcContext<'_>, code: EventRequest, sink: UnarySink<Empty>) {
        self.rt.block_on(
            self.hci_exports
                .register_event_handler(code.get_code() as u8, self.from_hci_evt_tx.clone()),
        );
        sink.success(Empty::default());
    }

    fn request_le_subevent(
        &mut self,
        _ctx: RpcContext<'_>,
        _code: EventRequest,
        _sink: UnarySink<Empty>,
    ) {
        unimplemented!()
    }

    fn send_acl(&mut self, _ctx: RpcContext<'_>, mut packet: AclPacket, sink: UnarySink<Empty>) {
        let acl_tx = self.hci_exports.acl_tx.clone();
        self.rt.block_on(async move {
            acl_tx.send(packet.take_data().into()).await.unwrap();
        });
        sink.success(Empty::default());
    }

    fn stream_events(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut resp: ServerStreamingSink<Event>,
    ) {
        let evt_rx = self.to_grpc_evt_rx.clone();

        self.rt.spawn(async move {
            while let Some(event) = evt_rx.lock().await.recv().await {
                let mut evt = Event::default();
                evt.set_payload(event.to_vec());
                resp.send((evt, WriteFlags::default())).await.unwrap();
            }
        });
    }

    fn stream_le_subevents(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut _resp: ServerStreamingSink<LeSubevent>,
    ) {
        unimplemented!()
    }

    fn stream_acl(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut resp: ServerStreamingSink<AclPacket>,
    ) {
        let acl_rx = self.hci_exports.acl_rx.clone();

        self.rt.spawn(async move {
            while let Some(data) = acl_rx.lock().await.recv().await {
                let mut packet = AclPacket::default();
                packet.set_data(data.to_vec());
                resp.send((packet, WriteFlags::default())).await.unwrap();
            }
        });
    }
}
