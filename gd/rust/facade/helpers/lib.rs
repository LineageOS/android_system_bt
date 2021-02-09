//! common facade & shim helpers

use bt_facade_proto::common::Data;
use bt_packets::hci::Packet;
use futures::sink::SinkExt;
use grpcio::*;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;

/// Wrapper so we can invoke callbacks
pub trait U8SliceRunnable {
    /// Do the thing
    fn run(&self, data: &[u8]);
}

/// Helper for interfacing channels with shim or gRPC boundaries
#[derive(Clone)]
pub struct RxAdapter<T> {
    rx: Arc<Mutex<Receiver<T>>>,
    running: bool,
}

impl<T: 'static + Packet + Send> RxAdapter<T> {
    /// New, from an unwrapped receiver
    pub fn new(rx: Receiver<T>) -> Self {
        Self::from_arc(Arc::new(Mutex::new(rx)))
    }

    /// New, from an already arc mutexed receiver
    pub fn from_arc(rx: Arc<Mutex<Receiver<T>>>) -> Self {
        Self { rx, running: false }
    }

    /// Stream out the channel over the provided sink
    pub fn stream_grpc(&mut self, ctx: RpcContext<'_>, mut sink: ServerStreamingSink<Data>) {
        assert!(!self.running);
        self.running = true;

        let clone_rx = self.rx.clone();
        ctx.spawn(async move {
            while let Some(payload) = clone_rx.lock().await.recv().await {
                let mut data = Data::default();
                data.set_payload(payload.to_vec());
                if let Err(e) = sink.send((data, WriteFlags::default())).await {
                    log::error!("failure sending data: {:?}", e);
                }
            }
        });
    }

    /// Stream out the channel over the provided shim runnable
    pub fn stream_runnable<R: 'static + U8SliceRunnable + Send>(
        &mut self,
        rt: &Arc<Runtime>,
        runnable: R,
    ) {
        assert!(!self.running);
        self.running = true;

        let clone_rx = self.rx.clone();
        rt.spawn(async move {
            while let Some(payload) = clone_rx.lock().await.recv().await {
                runnable.run(&payload.to_bytes());
            }
        });
    }
}
