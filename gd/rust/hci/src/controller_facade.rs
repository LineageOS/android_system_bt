//! Controller facade

use crate::controller::{null_terminated_to_string, ControllerExports};
use crate::Hci;
use bt_common::GrpcFacade;
use bt_facade_proto::controller_facade::{AddressMsg, NameMsg};
use bt_facade_proto::controller_facade_grpc::{create_controller_facade, ControllerFacade};
use bt_facade_proto::empty::Empty;
use bt_packets::hci::{ReadLocalNameBuilder, WriteLocalNameBuilder};
use gddi::{module, provides, Stoppable};
use grpcio::*;
use std::sync::Arc;

module! {
    controller_facade_module,
    providers {
        ControllerFacadeService => provide_facade,
    }
}

#[provides]
async fn provide_facade(exports: Arc<ControllerExports>, hci: Hci) -> ControllerFacadeService {
    ControllerFacadeService { exports, hci }
}

/// Controller facade service
#[allow(missing_docs)]
#[derive(Clone, Stoppable)]
pub struct ControllerFacadeService {
    pub exports: Arc<ControllerExports>,
    hci: Hci,
}

impl GrpcFacade for ControllerFacadeService {
    fn into_grpc(self) -> grpcio::Service {
        create_controller_facade(self)
    }
}

impl ControllerFacade for ControllerFacadeService {
    fn get_mac_address(&mut self, ctx: RpcContext<'_>, _req: Empty, sink: UnarySink<AddressMsg>) {
        let clone = self.clone();
        ctx.spawn(async move {
            let mut address = AddressMsg::new();
            address.set_address(clone.exports.address.bytes.to_vec());
            sink.success(address).await.unwrap();
        });
    }

    fn write_local_name(&mut self, ctx: RpcContext<'_>, req: NameMsg, sink: UnarySink<Empty>) {
        let mut clone = self.clone();
        let mut builder = WriteLocalNameBuilder { local_name: [0; 248] };
        builder.local_name[0..req.get_name().len()].copy_from_slice(req.get_name());
        ctx.spawn(async move {
            clone.hci.commands.send(builder.build()).await;
            sink.success(Empty::default()).await.unwrap();
        });
    }

    fn get_local_name(&mut self, ctx: RpcContext<'_>, _req: Empty, sink: UnarySink<NameMsg>) {
        let mut clone = self.clone();
        ctx.spawn(async move {
            let local_name = null_terminated_to_string(
                clone.hci.commands.send(ReadLocalNameBuilder {}).await.get_local_name(),
            )
            .into_bytes();
            let mut msg = NameMsg::new();
            msg.set_name(local_name);
            sink.success(msg).await.unwrap();
        });
    }
}
