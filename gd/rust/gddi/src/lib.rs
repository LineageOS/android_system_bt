//! Core dependency injection objects

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

pub use gddi_macros::{module, provides};

type InstanceBox = Box<dyn Any + Send + Sync>;
/// A box around a future for a provider that is safe to send between threads
pub type ProviderFutureBox = Box<dyn Future<Output = Box<dyn Any>> + Send + Sync>;
type ProviderFnBox = Box<dyn Fn(Arc<Registry>) -> Pin<ProviderFutureBox> + Send + Sync>;

/// Builder for Registry
pub struct RegistryBuilder {
    providers: HashMap<TypeId, Provider>,
}

/// Keeps track of central injection state
pub struct Registry {
    providers: Arc<Mutex<HashMap<TypeId, Provider>>>,
    instances: Arc<Mutex<HashMap<TypeId, InstanceBox>>>,
}

#[derive(Clone)]
struct Provider {
    f: Arc<ProviderFnBox>,
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryBuilder {
    /// Creates a new RegistryBuilder
    pub fn new() -> Self {
        RegistryBuilder {
            providers: HashMap::new(),
        }
    }

    /// Registers a module with this registry
    pub fn register_module<F>(&mut self, init: F)
    where
        F: Fn(&mut Self),
    {
        init(self);
    }

    /// Registers a provider function with this registry
    pub fn register_provider<T: 'static>(&mut self, f: ProviderFnBox) {
        self.providers
            .insert(TypeId::of::<T>(), Provider { f: Arc::new(f) });
    }

    /// Construct the Registry from this builder
    pub fn build(self) -> Registry {
        Registry {
            providers: Arc::new(Mutex::new(self.providers)),
            instances: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Registry {
    /// Gets an instance of a type, implicitly starting any dependencies if necessary
    pub async fn get<T: 'static + Clone + Send + Sync>(self: &Arc<Self>) -> T {
        let typeid = TypeId::of::<T>();
        {
            let instances = self.instances.lock().await;
            if let Some(value) = instances.get(&typeid) {
                return value
                    .downcast_ref::<T>()
                    .expect("was not correct type")
                    .clone();
            }
        }

        let casted = {
            let provider = { self.providers.lock().await[&typeid].clone() };
            let result = (provider.f)(self.clone()).await;
            (*result.downcast::<T>().expect("was not correct type")).clone()
        };

        let mut instances = self.instances.lock().await;
        instances.insert(typeid, Box::new(casted.clone()));

        casted
    }

    /// Inject an already created instance of T. Useful for config.
    pub async fn inject<T: 'static + Clone + Send + Sync>(self: &Arc<Self>, obj: T) {
        let mut instances = self.instances.lock().await;
        instances.insert(TypeId::of::<T>(), Box::new(obj));
    }
}
