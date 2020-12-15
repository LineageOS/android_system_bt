//! Main BT lifecycle support

use bt_common::GrpcFacade;
use bt_hal::rootcanal_hal::RootcanalConfig;
use bt_hal::snoop::{SnoopConfig, SnoopMode};
use gddi::{module, Registry, RegistryBuilder, Stoppable};
use std::sync::Arc;
use tokio::runtime::Runtime;

module! {
    stack_module,
    submodules {
        bt_hal::hal_module,
        bt_hci::hci_module,
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
            self.registry.inject(RootcanalConfig::new("127.0.0.1", port)).await;
        }
    }

    /// Configures snoop. If the path is provided, full logging is turned on
    pub async fn configure_snoop(&self, path: Option<String>) {
        let mut config = SnoopConfig::default();
        if let Some(path) = path {
            config.set_path(path);
            config.set_mode(SnoopMode::Full);
        }
        self.registry.inject(config).await;
    }

    /// Helper forwarding to underlying registry
    pub async fn get<T: 'static + Clone + Send + Sync + Stoppable>(&self) -> T {
        self.registry.get::<T>().await
    }

    /// Helper to get a grpc service
    pub async fn get_grpc<T: 'static + Clone + Send + Sync + GrpcFacade + Stoppable>(
        &self,
    ) -> grpcio::Service {
        self.get::<T>().await.into_grpc()
    }

    /// Stop the stack
    pub async fn stop(&mut self) {
        self.registry.stop_all().await;
    }
}
