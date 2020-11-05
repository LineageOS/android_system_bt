//! Bluetooth testing root facade service

mod rootservice_grpc;

/// Refer to the following on why we are doing this and for possible solutions:
/// https://github.com/tikv/grpc-rs/issues/276
pub mod empty {
    pub use protobuf::well_known_types::Empty;
}

use bt_facade_common_proto::common;
use bt_facade_rootservice_proto::rootservice;
use rootservice::*;
use rootservice_grpc::{create_root_facade, RootFacade};

use bt_hal::rootcanal_hal::{RootcanalConfig, RootcanalHal};
use bt_hci::facade::HciLayerFacadeService;
use bt_hci::Hci;

use tokio::runtime::Runtime;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;

use grpcio::*;

use std::sync::Arc;

use futures::executor::block_on;

/// Bluetooth testing root facade service
#[derive(Clone)]
pub struct RootFacadeService {
    rt: Arc<Runtime>,
    manager: FacadeServiceManager,
}

impl RootFacadeService {
    /// Create a new instance of the root facade service
    pub fn create(
        rt: Arc<Runtime>,
        grpc_port: u16,
        rootcanal_port: Option<u16>,
    ) -> grpcio::Service {
        create_root_facade(Self {
            rt: rt.clone(),
            manager: FacadeServiceManager::create(rt, grpc_port, rootcanal_port),
        })
    }
}

impl RootFacade for RootFacadeService {
    fn start_stack(
        &mut self,
        _ctx: RpcContext<'_>,
        req: StartStackRequest,
        sink: UnarySink<StartStackResponse>,
    ) {
        self.rt.block_on(self.manager.start(req)).unwrap();
        sink.success(StartStackResponse::default());
    }

    fn stop_stack(
        &mut self,
        _ctx: RpcContext<'_>,
        _req: StopStackRequest,
        sink: UnarySink<StopStackResponse>,
    ) {
        self.rt.block_on(self.manager.stop()).unwrap();
        sink.success(StopStackResponse::default());
    }
}

#[derive(Debug)]
enum LifecycleCommand {
    Start {
        req: StartStackRequest,
        done: oneshot::Sender<()>,
    },
    Stop {
        done: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
struct FacadeServiceManager {
    lifecycle_tx: Sender<LifecycleCommand>,
}

/// Result type
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

impl FacadeServiceManager {
    fn create(rt: Arc<Runtime>, grpc_port: u16, rootcanal_port: Option<u16>) -> Self {
        let (tx, mut rx) = channel::<LifecycleCommand>(1);
        let local_rt = rt.clone();
        local_rt.spawn(async move {
            let mut server: Option<Server> = None;
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    LifecycleCommand::Start { req, done } => {
                        server =
                            Some(Self::start_internal(&rt, req, grpc_port, rootcanal_port).await);
                        done.send(()).unwrap();
                    }
                    LifecycleCommand::Stop { done } => {
                        if let Some(s) = &mut server {
                            block_on(s.shutdown()).unwrap();
                            server = None;
                        }
                        done.send(()).unwrap();
                    }
                }
            }
        });

        Self { lifecycle_tx: tx }
    }

    async fn start(&self, req: StartStackRequest) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.lifecycle_tx
            .send(LifecycleCommand::Start { req, done: tx })
            .await?;
        rx.await?;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.lifecycle_tx
            .send(LifecycleCommand::Stop { done: tx })
            .await?;
        rx.await?;
        Ok(())
    }

    // TODO this is messy and needs to be overhauled to support bringing up the stack to partial
    // layers. Will be cleaned up soon.
    async fn start_internal(
        rt: &Arc<Runtime>,
        _req: StartStackRequest,
        grpc_port: u16,
        rootcanal_port: Option<u16>,
    ) -> Server {
        let env = Arc::new(Environment::new(2));
        let hal_exports = RootcanalHal::start(
            RootcanalConfig::new(rootcanal_port.unwrap(), "127.0.0.1"),
            Arc::clone(&rt),
        )
        .await
        .unwrap();
        let hci_exports = Hci::start(hal_exports, Arc::clone(&rt));
        let mut server = ServerBuilder::new(env)
            .register_service(HciLayerFacadeService::create(hci_exports, Arc::clone(&rt)))
            .bind("0.0.0.0", grpc_port)
            .build()
            .unwrap();
        server.start();
        server
    }
}
