//! HCI layer facade

mod facade_grpc;

use hci_layer_facade_proto::facade;
use facade_grpc::{HciLayerFacade, create_hci_layer_facade};
use facade::*;

use futures::sink::SinkExt;
use tokio::runtime::Runtime;

use crate::HciExports;

use futures::prelude::*;
use grpcio::*;

use std::sync::Arc;

/// HCI layer facade service
#[derive(Clone)]
pub struct HciLayerFacadeService {
    /// HCI interface
    pub hci_exports: HciExports,
    /// Tokio runtime
    pub rt: Arc<Runtime>,
}

/// Refer to the following on why we are doing this and for possible solutions:
/// https://github.com/tikv/grpc-rs/issues/276
pub mod empty {
    pub use protobuf::well_known_types::Empty;
}
use empty::Empty;

impl HciLayerFacadeService {
    /// Create a new instance of HCI layer facade service
    pub fn create(hci_exports: HciExports, rt: Arc<Runtime>) -> grpcio::Service {
        create_hci_layer_facade(Self { hci_exports, rt })
    }
}

impl HciLayerFacade for HciLayerFacadeService {
    fn enqueue_command_with_complete(
        &mut self,
        ctx: RpcContext<'_>,
        mut cmd: CommandMsg,
        sink: UnarySink<Empty>,
    ) {
        self.rt.block_on(self.hci_exports.enqueue_command_with_complete(cmd.take_command().into()));

        let f = sink
            .success(Empty::default())
            .map_err(|e: grpcio::Error| {
                println!("failed to handle enqueue_command_with_complete request: {:?}", e)
            })
            .map(|_| ());

        ctx.spawn(f);
    }

    fn enqueue_command_with_status(
        &mut self,
        ctx: RpcContext<'_>,
        mut cmd: CommandMsg,
        sink: UnarySink<Empty>,
    ) {
        self.rt.block_on(self.hci_exports.enqueue_command_with_complete(cmd.take_command().into()));

        let f = sink
            .success(Empty::default())
            .map_err(|e: grpcio::Error| {
                println!("failed to handle enqueue_command_with_status request: {:?}", e)
            })
            .map(|_| ());

        ctx.spawn(f);
    }

    fn register_event_handler(
        &mut self,
        ctx: RpcContext<'_>,
        code: EventCodeMsg,
        sink: UnarySink<Empty>,
    ) {
        self.rt.block_on(self.hci_exports.register_event_handler(code.get_code() as u8));

        let f = sink
            .success(Empty::default())
            .map_err(|e: grpcio::Error| {
                println!("failed to handle enqueue_command_with_status request: {:?}", e)
            })
            .map(|_| ());

        ctx.spawn(f);
    }

    fn register_le_event_handler(
        &mut self,
        _ctx: RpcContext<'_>,
        _code: LeSubeventCodeMsg,
        _sink: UnarySink<Empty>,
    ) {
        unimplemented!()
    }

    fn send_acl_data(&mut self, _ctx: RpcContext<'_>, _data: AclMsg, _sink: UnarySink<Empty>) {
        unimplemented!()
    }

    fn fetch_events(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut resp: ServerStreamingSink<EventMsg>,
    ) {
        let evt_rx = self.hci_exports.evt_rx.clone();

        self.rt.spawn(async move {
            while let Some(event) = evt_rx.lock().await.recv().await {
                let mut evt = EventMsg::default();
                evt.set_event(event.to_vec());
                resp.send((evt, WriteFlags::default())).await.unwrap();
            }
        });
    }

    fn fetch_le_subevents(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut _resp: ServerStreamingSink<LeSubeventMsg>,
    ) {
        unimplemented!()
    }

    fn fetch_acl_packets(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: Empty,
        mut _resp: ServerStreamingSink<AclMsg>,
    ) {
        unimplemented!()
    }
}
