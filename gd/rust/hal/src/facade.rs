//! BT HCI HAL facade

use bt_hal_proto::empty::Empty;
use bt_hal_proto::facade::*;
use bt_hal_proto::facade_grpc::{create_hci_hal_facade, HciHalFacade};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use futures::sink::SinkExt;
use grpcio::*;

use std::sync::Arc;

use crate::HalExports;

use bt_packet::{HciCommand, HciEvent, RawPacket};

/// HCI HAL facade service
#[derive(Clone)]
pub struct HciHalFacadeService {
    rt: Arc<Runtime>,
    cmd_tx: mpsc::UnboundedSender<HciCommand>,
    evt_rx: Arc<Mutex<mpsc::UnboundedReceiver<HciEvent>>>,
    acl_tx: mpsc::UnboundedSender<RawPacket>,
    acl_rx: Arc<Mutex<mpsc::UnboundedReceiver<HciEvent>>>,
}

impl HciHalFacadeService {
    /// Create a new instance of HCI HAL facade service
    pub fn create(hal_exports: HalExports, rt: Arc<Runtime>) -> grpcio::Service {
        create_hci_hal_facade(Self {
            rt,
            cmd_tx: hal_exports.cmd_tx,
            evt_rx: Arc::new(Mutex::new(hal_exports.evt_rx)),
            acl_tx: hal_exports.acl_tx,
            acl_rx: Arc::new(Mutex::new(hal_exports.acl_rx)),
        })
    }
}

impl HciHalFacade for HciHalFacadeService {
    fn send_command(&mut self, _ctx: RpcContext<'_>, mut cmd: Command, sink: UnarySink<Empty>) {
        self.cmd_tx.send(cmd.take_payload().into()).unwrap();
        sink.success(Empty::default());
    }

    fn send_acl(&mut self, _ctx: RpcContext<'_>, mut acl: AclPacket, sink: UnarySink<Empty>) {
        self.acl_tx.send(acl.take_payload().into()).unwrap();
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
