//! Starts the facade services that allow us to test the Bluetooth stack

#[macro_use]
extern crate clap;
use clap::{App, Arg};

#[macro_use]
extern crate lazy_static;

use grpcio::*;

use futures::channel::mpsc;
use futures::executor::block_on;
use futures::stream::StreamExt;

use bluetooth_with_facades::RootFacadeService;

use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;

use tokio::net::TcpStream;

use tokio::runtime::Runtime;

use nix::sys::signal;

fn main() {
    let sigint = install_sigint();
    let rt = Arc::new(Runtime::new().unwrap());
    rt.block_on(async_main(Arc::clone(&rt), sigint));
}

async fn async_main(rt: Arc<Runtime>, mut sigint: mpsc::UnboundedReceiver<()>) {
    let matches = App::new("bluetooth_with_facades")
        .about("The bluetooth stack, with testing facades enabled and exposed via gRPC.")
        .arg(
            Arg::with_name("root-server-port")
                .long("root-server-port")
                .default_value("8897")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("grpc-port")
                .long("grpc-port")
                .default_value("8899")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("signal-port")
                .long("signal-port")
                .default_value("8895")
                .takes_value(true),
        )
        .get_matches();

    let root_server_port = value_t!(matches, "root-server-port", u16).unwrap();
    let grpc_port = value_t!(matches, "grpc-port", u16).unwrap();
    let signal_port = value_t!(matches, "signal-port", u16).unwrap();

    println!(
        "root server port: {}, grpc port: {}, signal port {}",
        root_server_port, grpc_port, signal_port
    );

    let env = Arc::new(Environment::new(2));
    let mut server = ServerBuilder::new(env)
        .register_service(RootFacadeService::create(rt))
        .bind("0.0.0.0", root_server_port)
        .build()
        .unwrap();

    indicate_started(signal_port).await;
    sigint.next().await;
    block_on(server.shutdown()).unwrap();
}

async fn indicate_started(signal_port: u16) {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), signal_port);
    let stream = TcpStream::connect(address).await.unwrap();
    stream.shutdown(Shutdown::Both).unwrap();
}

// TODO: remove as this is a temporary nix-based hack to catch SIGINT
fn install_sigint() -> mpsc::UnboundedReceiver<()> {
    let (tx, rx) = mpsc::unbounded();
    *SIGINT_TX.lock().unwrap() = Some(tx);

    let sig_action = signal::SigAction::new(
        signal::SigHandler::Handler(handle_sigint),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );
    unsafe {
        signal::sigaction(signal::SIGINT, &sig_action).unwrap();
    }

    rx
}

lazy_static! {
    static ref SIGINT_TX: Mutex<Option<mpsc::UnboundedSender<()>>> = Mutex::new(None);
}

extern "C" fn handle_sigint(_: i32) {
    let mut sigint_tx = SIGINT_TX.lock().unwrap();
    if let Some(tx) = &*sigint_tx {
        println!("Stopping gRPC root server due to SIGINT");
        tx.unbounded_send(()).unwrap();
    }
    *sigint_tx = None;
}
