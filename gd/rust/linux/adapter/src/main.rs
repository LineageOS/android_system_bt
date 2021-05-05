use bt_topshim::btif;
use bt_topshim::btif::{ffi, BluetoothCallbacks, BluetoothInterface};
use bt_topshim::topstack;
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::sleep;

// DO NOT REMOVE
// Required so that bt_shim is linked into the final image
extern crate bt_shim;

enum Callbacks {
    AdapterStateChanged(btif::BtState),
    AdapterPropertiesChanged(i32, i32, Vec<ffi::BtProperty>),
    RemoteDevicePropertiesChanged(i32, ffi::RustRawAddress, i32, Vec<ffi::BtProperty>),
    DeviceFound(i32, Vec<ffi::BtProperty>),
    DiscoveryStateChanged(btif::BtDiscoveryState),
}
struct Context {
    tx: Sender<Callbacks>,
    rx: Receiver<Callbacks>,
    callbacks: Arc<BluetoothCallbacks>,
    intf: BluetoothInterface,
}

fn make_context(intf: BluetoothInterface) -> Context {
    let (tx, rx) = mpsc::channel::<Callbacks>(1);

    let (tx1, tx2, tx3, tx4, tx5) = (tx.clone(), tx.clone(), tx.clone(), tx.clone(), tx.clone());
    let cb = Arc::new(BluetoothCallbacks {
        adapter_state_changed: Box::new(move |state| {
            let txl = tx1.clone();
            topstack::get_runtime().spawn(async move {
                txl.send(Callbacks::AdapterStateChanged(state)).await;
            });
        }),
        adapter_properties_changed: Box::new(move |status, count, props| {
            let txl = tx2.clone();
            topstack::get_runtime().spawn(async move {
                txl.send(Callbacks::AdapterPropertiesChanged(status, count, props)).await;
            });
        }),
        remote_device_properties_changed: Box::new(move |status, address, count, props| {
            let txl = tx5.clone();
            topstack::get_runtime().spawn(async move {
                txl.send(Callbacks::RemoteDevicePropertiesChanged(status, address, count, props));
            });
        }),
        device_found: Box::new(move |count, props| {
            let txl = tx3.clone();
            topstack::get_runtime().spawn(async move {
                txl.send(Callbacks::DeviceFound(count, props)).await;
            });
        }),
        discovery_state_changed: Box::new(move |state| {
            let txl = tx4.clone();
            topstack::get_runtime().spawn(async move {
                txl.send(Callbacks::DiscoveryStateChanged(state)).await;
            });
        }),
        pin_request: Box::new(move |_address, _bdname, _cod, _min_16_digit| {
            println!("Pin request callback");
        }),
        ssp_request: Box::new(move |_address, _bdname, _cod, _variant, _passkey| {
            println!("Ssp request callback");
        }),
        bond_state_changed: Box::new(move |_status, _address, _state| {
            println!("Bond state changed");
        }),
        acl_state_changed: Box::new(move |_status, _address, _state, _hci_reason| {
            println!("Acl state changed");
        }),
    });

    return Context { tx, rx, callbacks: cb, intf };
}

async fn mainloop(context: &mut Context) {
    'main: while let Some(cb) = context.rx.recv().await {
        match cb {
            Callbacks::AdapterStateChanged(state) => {
                println!("Adapter state changed to {}", state.to_i32().unwrap());

                if state == btif::BtState::On {
                    context.intf.get_adapter_properties();
                }
            }
            Callbacks::AdapterPropertiesChanged(status, _count, properties) => {
                if status != 0 {
                    println!("Failed property change: {}", status);
                }

                for p in properties {
                    let proptype = match btif::BtPropertyType::from_i32(p.prop_type) {
                        Some(x) => x,
                        None => btif::BtPropertyType::Unknown,
                    };
                    println!("Property {:?} is ({:?})", proptype, p.val);
                }

                // Scan for 5s and then cancel
                println!("Starting discovery");
                context.intf.start_discovery();
            }
            Callbacks::RemoteDevicePropertiesChanged(status, address, _count, properties) => {
                if status != 0 {
                    println!("Failed remote property change: {}", status);
                }

                println!("Properties for {:?}", address.address);

                for p in properties {
                    let proptype = match btif::BtPropertyType::from_i32(p.prop_type) {
                        Some(x) => x,
                        None => btif::BtPropertyType::Unknown,
                    };
                    println!("Property {:?} is ({:?})", proptype, p.val);
                }
            }
            Callbacks::DeviceFound(_count, properties) => {
                print!("Device found: ");

                for p in properties {
                    let proptype = match btif::BtPropertyType::from_i32(p.prop_type) {
                        Some(x) => x,
                        None => btif::BtPropertyType::Unknown,
                    };

                    if proptype == btif::BtPropertyType::BdAddr {
                        print!(" Addr[{:?}]", p.val);
                    } else if proptype == btif::BtPropertyType::BdName {
                        print!(
                            " Name[{:?}]",
                            p.val.iter().map(|u| char::try_from(*u).unwrap()).collect::<String>()
                        );
                    }
                }

                println!("");
            }
            Callbacks::DiscoveryStateChanged(state) => {
                if state == btif::BtDiscoveryState::Started {
                    sleep(Duration::from_millis(5000)).await;
                    context.intf.cancel_discovery();

                    break 'main;
                }
            }
        }
    }
}

fn main() {
    println!("Bluetooth Adapter Daemon");

    // Drop the first arg (which is the binary name)
    let all_args: Vec<String> = env::args().collect();
    let args = all_args[1..].to_vec();

    let intf = BluetoothInterface::new();
    let mut context = make_context(intf);

    topstack::get_runtime().block_on(async move {
        if !context.intf.initialize(context.callbacks.clone(), args) {
            panic!("Couldn't initialize bluetooth interface!");
        }

        println!("Enabling...");
        context.intf.enable();

        println!("Running mainloop now");
        mainloop(&mut context).await;

        println!("Disabling and exiting...");
        context.intf.disable();
    });
}
