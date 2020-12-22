//! HCI layer facade

use crate::{EventRegistry, RawCommandSender};
use bt_common::GrpcFacade;
use bt_facade_proto::common::Data;
use bt_facade_proto::empty::Empty;
use bt_facade_proto::hci_facade::EventRequest;
use bt_facade_proto::hci_facade_grpc::{create_hci_facade, HciFacade};
use bt_hal::AclHal;
use bt_packets::hci::{
    AclPacket, CommandPacket, EventCode, EventPacket, LeMetaEventPacket, SubeventCode,
};
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
        HciFacadeService => provide_facade,
    }
}

#[provides]
async fn provide_facade(
    commands: RawCommandSender,
    events: EventRegistry,
    acl: AclHal,
    rt: Arc<Runtime>,
) -> HciFacadeService {
    let (evt_tx, evt_rx) = channel::<EventPacket>(10);
    let (le_evt_tx, le_evt_rx) = channel::<LeMetaEventPacket>(10);
    HciFacadeService {
        commands,
        events,
        acl,
        rt,
        evt_tx,
        evt_rx: Arc::new(Mutex::new(evt_rx)),
        le_evt_tx,
        le_evt_rx: Arc::new(Mutex::new(le_evt_rx)),
    }
}

/// HCI layer facade service
#[allow(missing_docs)]
#[derive(Clone, Stoppable)]
pub struct HciFacadeService {
    pub commands: RawCommandSender,
    events: EventRegistry,
    pub acl: AclHal,
    rt: Arc<Runtime>,
    evt_tx: Sender<EventPacket>,
    pub evt_rx: Arc<Mutex<Receiver<EventPacket>>>,
    le_evt_tx: Sender<LeMetaEventPacket>,
    pub le_evt_rx: Arc<Mutex<Receiver<LeMetaEventPacket>>>,
}

impl HciFacadeService {
    /// Register for the event & plug in the channel to get them back on
    pub async fn register_event(&self, code: u32) {
        self.events.clone().register(EventCode::from_u32(code).unwrap(), self.evt_tx.clone()).await;
    }

    /// Register for the le event & plug in the channel to get them back on
    pub async fn register_le_event(&self, code: u32) {
        self.events
            .clone()
            .register_le(SubeventCode::from_u32(code).unwrap(), self.le_evt_tx.clone())
            .await;
    }
}

impl GrpcFacade for HciFacadeService {
    fn into_grpc(self) -> grpcio::Service {
        create_hci_facade(self)
    }
}

impl HciFacade for HciFacadeService {
    fn send_command(&mut self, _ctx: RpcContext<'_>, mut data: Data, sink: UnarySink<Empty>) {
        self.rt
            .block_on(self.commands.send(CommandPacket::parse(&data.take_payload()).unwrap()))
            .unwrap();
        sink.success(Empty::default());
    }

    fn request_event(&mut self, _ctx: RpcContext<'_>, req: EventRequest, sink: UnarySink<Empty>) {
        self.rt.block_on(self.register_event(req.get_code()));
        sink.success(Empty::default());
    }

    fn request_le_subevent(
        &mut self,
        _ctx: RpcContext<'_>,
        req: EventRequest,
        sink: UnarySink<Empty>,
    ) {
        self.rt.block_on(self.register_le_event(req.get_code()));
        sink.success(Empty::default());
    }

    fn send_acl(&mut self, _ctx: RpcContext<'_>, mut packet: Data, sink: UnarySink<Empty>) {
        let acl_tx = self.acl.tx.clone();
        self.rt.block_on(async move {
            acl_tx.send(AclPacket::parse(&packet.take_payload()).unwrap()).await.unwrap();
        });
        sink.success(Empty::default());
    }

    fn stream_events(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut resp: ServerStreamingSink<Data>,
    ) {
        let evt_rx = self.evt_rx.clone();

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
        let evt_rx = self.le_evt_rx.clone();

        self.rt.spawn(async move {
            while let Some(event) = evt_rx.lock().await.recv().await {
                let mut evt = Data::default();
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
        let acl_rx = self.acl.rx.clone();

        self.rt.spawn(async move {
            while let Some(data) = acl_rx.lock().await.recv().await {
                let mut packet = Data::default();
                packet.set_payload(data.to_vec());
                resp.send((packet, WriteFlags::default())).await.unwrap();
            }
        });
    }
}
