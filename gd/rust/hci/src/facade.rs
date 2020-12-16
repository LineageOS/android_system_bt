//! HCI layer facade

use crate::HciExports;
use bt_common::GrpcFacade;
use bt_facade_proto::common::Data;
use bt_facade_proto::empty::Empty;
use bt_facade_proto::hci_facade::EventRequest;
use bt_facade_proto::hci_facade_grpc::{create_hci_layer_facade, HciLayerFacade};
use bt_packets::hci;
use futures::sink::SinkExt;
use gddi::{module, provides, Stoppable};
use grpcio::*;
use num_traits::FromPrimitive;
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
    let (from_hci_evt_tx, to_grpc_evt_rx) = channel::<hci::EventPacket>(10);
    let (from_hci_le_evt_tx, to_grpc_le_evt_rx) = channel::<hci::LeMetaEventPacket>(10);
    HciLayerFacadeService {
        hci_exports,
        rt,
        from_hci_evt_tx,
        to_grpc_evt_rx: Arc::new(Mutex::new(to_grpc_evt_rx)),
        from_hci_le_evt_tx,
        to_grpc_le_evt_rx: Arc::new(Mutex::new(to_grpc_le_evt_rx)),
    }
}

/// HCI layer facade service
#[derive(Clone, Stoppable)]
pub struct HciLayerFacadeService {
    hci_exports: HciExports,
    rt: Arc<Runtime>,
    from_hci_evt_tx: Sender<hci::EventPacket>,
    to_grpc_evt_rx: Arc<Mutex<Receiver<hci::EventPacket>>>,
    from_hci_le_evt_tx: Sender<hci::LeMetaEventPacket>,
    to_grpc_le_evt_rx: Arc<Mutex<Receiver<hci::LeMetaEventPacket>>>,
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
        mut data: Data,
        sink: UnarySink<Empty>,
    ) {
        self.rt
            .block_on(
                self.hci_exports.send_raw(hci::CommandPacket::parse(&data.take_payload()).unwrap()),
            )
            .unwrap();
        sink.success(Empty::default());
    }

    fn send_command_with_status(
        &mut self,
        _ctx: RpcContext<'_>,
        mut data: Data,
        sink: UnarySink<Empty>,
    ) {
        self.rt
            .block_on(
                self.hci_exports.send_raw(hci::CommandPacket::parse(&data.take_payload()).unwrap()),
            )
            .unwrap();
        sink.success(Empty::default());
    }

    fn request_event(&mut self, _ctx: RpcContext<'_>, code: EventRequest, sink: UnarySink<Empty>) {
        self.rt.block_on(self.hci_exports.register_event_handler(
            hci::EventCode::from_u32(code.get_code()).unwrap(),
            self.from_hci_evt_tx.clone(),
        ));
        sink.success(Empty::default());
    }

    fn request_le_subevent(
        &mut self,
        _ctx: RpcContext<'_>,
        code: EventRequest,
        sink: UnarySink<Empty>,
    ) {
        self.rt.block_on(self.hci_exports.register_le_event_handler(
            hci::SubeventCode::from_u32(code.get_code()).unwrap(),
            self.from_hci_le_evt_tx.clone(),
        ));
        sink.success(Empty::default());
    }

    fn send_acl(&mut self, _ctx: RpcContext<'_>, mut packet: Data, sink: UnarySink<Empty>) {
        let acl_tx = self.hci_exports.acl_tx.clone();
        self.rt.block_on(async move {
            acl_tx.send(hci::AclPacket::parse(&packet.take_payload()).unwrap()).await.unwrap();
        });
        sink.success(Empty::default());
    }

    fn stream_events(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut resp: ServerStreamingSink<Data>,
    ) {
        let evt_rx = self.to_grpc_evt_rx.clone();

        self.rt.spawn(async move {
            while let Some(event) = evt_rx.lock().await.recv().await {
                let mut evt = Data::default();
                evt.set_payload(event.to_vec());
                resp.send((evt, WriteFlags::default())).await.unwrap();
            }
        });
    }

    fn stream_le_subevents(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut resp: ServerStreamingSink<Data>,
    ) {
        let evt_rx = self.to_grpc_le_evt_rx.clone();

        self.rt.spawn(async move {
            while let Some(event) = evt_rx.lock().await.recv().await {
                let mut evt = LeSubevent::default();
                evt.set_payload(event.to_vec());
                resp.send((evt, WriteFlags::default())).await.unwrap();
            }
        });
    }

    fn stream_acl(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut resp: ServerStreamingSink<Data>,
    ) {
        let acl_rx = self.hci_exports.acl_rx.clone();

        self.rt.spawn(async move {
            while let Some(data) = acl_rx.lock().await.recv().await {
                let mut packet = Data::default();
                packet.set_payload(data.to_vec());
                resp.send((packet, WriteFlags::default())).await.unwrap();
            }
        });
    }
}
