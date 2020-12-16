//! BT HCI HAL facade

use crate::HalExports;
use bt_common::GrpcFacade;
use bt_facade_proto::empty::Empty;
use bt_facade_proto::hal_facade::*;
use bt_facade_proto::hal_facade_grpc::{create_hci_hal_facade, HciHalFacade};
use bt_packet::{HciCommand, HciEvent, RawPacket};
use futures::sink::SinkExt;
use gddi::{module, provides, Stoppable};
use grpcio::*;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex};

module! {
    hal_facade_module,
    providers {
        HciHalFacadeService => provide_facade,
    }
}

#[provides]
async fn provide_facade(hal_exports: HalExports, rt: Arc<Runtime>) -> HciHalFacadeService {
    HciHalFacadeService {
        rt,
        cmd_tx: hal_exports.cmd_tx,
        evt_rx: hal_exports.evt_rx,
        acl_tx: hal_exports.acl_tx,
        acl_rx: hal_exports.acl_rx,
    }
}

/// HCI HAL facade service
#[derive(Clone, Stoppable)]
pub struct HciHalFacadeService {
    rt: Arc<Runtime>,
    cmd_tx: mpsc::Sender<HciCommand>,
    evt_rx: Arc<Mutex<mpsc::Receiver<HciEvent>>>,
    acl_tx: mpsc::Sender<RawPacket>,
    acl_rx: Arc<Mutex<mpsc::Receiver<HciEvent>>>,
}

impl GrpcFacade for HciHalFacadeService {
    fn into_grpc(self) -> grpcio::Service {
        create_hci_hal_facade(self)
    }
}

impl HciHalFacade for HciHalFacadeService {
    fn send_command(&mut self, _ctx: RpcContext<'_>, mut cmd: Command, sink: UnarySink<Empty>) {
        let cmd_tx = self.cmd_tx.clone();
        self.rt.block_on(async move {
            cmd_tx.send(cmd.take_payload().into()).await.unwrap();
        });
        sink.success(Empty::default());
    }

    fn send_acl(&mut self, _ctx: RpcContext<'_>, mut acl: AclPacket, sink: UnarySink<Empty>) {
        let acl_tx = self.acl_tx.clone();
        self.rt.block_on(async move {
            acl_tx.send(acl.take_payload().into()).await.unwrap();
        });
        sink.success(Empty::default());
    }

    fn send_sco(&mut self, _ctx: RpcContext<'_>, _sco: ScoPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn send_iso(&mut self, _ctx: RpcContext<'_>, _iso: IsoPacket, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn stream_events(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        mut sink: ServerStreamingSink<Event>,
    ) {
        let evt_rx = self.evt_rx.clone();
        self.rt.spawn(async move {
            while let Some(event) = evt_rx.lock().await.recv().await {
                let mut output = Event::default();
                output.set_payload(event.to_vec());
                sink.send((output, WriteFlags::default())).await.unwrap();
            }
        });
    }

    fn stream_acl(
        &mut self,
        _ctx: RpcContext<'_>,
        _: Empty,
        mut sink: ServerStreamingSink<AclPacket>,
    ) {
        let acl_rx = self.acl_rx.clone();
        self.rt.spawn(async move {
            while let Some(acl) = acl_rx.lock().await.recv().await {
                let mut output = AclPacket::default();
                output.set_payload(acl.to_vec());
                sink.send((output, WriteFlags::default())).await.unwrap();
            }
        });
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
