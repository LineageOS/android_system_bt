//! Main BT lifecycle support

use bt_hal::hal_module;
use bt_hci::hci_module;
use gddi::{module, Registry, RegistryBuilder, Stoppable};
use bt_hal::rootcanal_hal::RootcanalConfig;
use std::sync::Arc;
use tokio::runtime::Runtime;
use bt_common::GrpcFacade;

module! {
    stack_module,
    submodules {
        hal_module,
        hci_module,
    }
}

/// Central state manager
pub struct Stack {
    registry: Arc<Registry>,
}

impl Stack {
    /// Construct a new Stack
    pub async fn new(rt: Arc<Runtime>) -> Self {
        let registry = Arc::new(RegistryBuilder::new().register_module(stack_module).build());
        registry.inject(rt).await;

        Self { registry }
    }

    /// Helper to set the rootcanal port
    pub async fn set_rootcanal_port(&self, port: Option<u16>) {
        if let Some(port) = port {
            self.registry
                .inject(RootcanalConfig::new("127.0.0.1", port))
                .await;
        }
    }

    /// Helper forwarding to underlying registry
    pub async fn get<T: 'static + Clone + Send + Sync + Stoppable>(&self) -> T {
        self.registry.get::<T>().await
    }

    /// Helper to get a grpc service
    pub async fn get_grpc<T: 'static + Clone + Send + Sync + GrpcFacade + Stoppable>(&self) -> grpcio::Service {
        self.get::<T>().await.into_grpc()
    }

    /// Stop the stack
    pub async fn stop(&mut self) {
        self.registry.stop_all().await;
    }
}
