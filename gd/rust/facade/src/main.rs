//! Starts the facade services that allow us to test the Bluetooth stack

#[macro_use]
extern crate clap;
use clap::{App, Arg};

fn main() {
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
}
