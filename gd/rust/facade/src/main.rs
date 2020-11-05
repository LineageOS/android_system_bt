//! Starts the facade services that allow us to test the Bluetooth stack

#[macro_use]
extern crate clap;
use clap::{App, Arg};

use grpcio::*;

use futures::channel::oneshot;
use futures::executor::block_on;

use bluetooth_with_facades::RootFacadeService;

use std::io::{self, Read};
use std::sync::Arc;
use std::thread;

use tokio::runtime::Runtime;

fn main() {
    let rt = Arc::new(Runtime::new().unwrap());
    let runtime = Arc::clone(&rt);
    runtime.block_on(async_main(rt));
}

async fn async_main(rt: Arc<Runtime>) {
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

    let (tx, rx) = oneshot::channel();

    thread::spawn(move || {
        println!("Press ENTER to exit...");
        let _ = io::stdin().read(&mut [0]).unwrap();
        tx.send(())
    });
    block_on(rx).unwrap();
    block_on(server.shutdown()).unwrap();
}
