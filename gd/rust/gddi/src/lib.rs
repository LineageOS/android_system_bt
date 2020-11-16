//! Core dependency injection objects

use std::collections::HashMap;

use std::any::Any;
use std::any::TypeId;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub use gddi_macros::{module, provides};

/// Keeps track of central injection state
pub struct Registry {
    providers: HashMap<TypeId, Provider>,
}

struct Provider {
    f: Box<dyn Fn(Arc<Registry>) -> Pin<Box<dyn Future<Output = Box<dyn Any>>>>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Creates a new registry
    pub fn new() -> Self {
        Registry {
            providers: HashMap::new(),
        }
    }

    /// Registers a module with this registry
    pub fn register_module<F>(&mut self, init: F)
    where
        F: Fn(&mut Registry),
    {
        init(self);
    }

    /// Registers a provider function with this registry
    pub fn register_provider<T: 'static>(
        &mut self,
        f: Box<dyn Fn(Arc<Registry>) -> Pin<Box<dyn Future<Output = Box<dyn Any>>>>>,
    ) {
        self.providers.insert(TypeId::of::<T>(), Provider { f });
    }

    /// Gets an instance of a type, implicitly starting any dependencies if necessary
    pub async fn get<T: 'static + Clone>(self: &Arc<Self>) -> T {
        let provider = &self.providers[&TypeId::of::<T>()];
        let result = (provider.f)(self.clone()).await;
        *result.downcast::<T>().expect("was not correct type")
    }
}
