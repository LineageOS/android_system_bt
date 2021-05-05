use bt_topshim::btif::BluetoothInterface;
use bt_topshim::topstack;

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;

use dbus_crossroads::Crossroads;

use dbus_projection::DisconnectWatcher;

use dbus_tokio::connection;

use futures::future;

use btstack::bluetooth::btif_bluetooth_callbacks;
use btstack::bluetooth::Bluetooth;
use btstack::bluetooth_gatt::BluetoothGatt;
use btstack::Stack;

use std::error::Error;
use std::sync::{Arc, Mutex};

mod dbus_arg;
mod iface_bluetooth;
mod iface_bluetooth_gatt;

const DBUS_SERVICE_NAME: &str = "org.chromium.bluetooth";
const OBJECT_BLUETOOTH: &str = "/org/chromium/bluetooth/adapter";
const OBJECT_BLUETOOTH_GATT: &str = "/org/chromium/bluetooth/gatt";

/// Runs the Bluetooth daemon serving D-Bus IPC.
fn main() -> Result<(), Box<dyn Error>> {
    let (tx, rx) = Stack::create_channel();

    let intf = Arc::new(Mutex::new(BluetoothInterface::new()));
    let bluetooth = Arc::new(Mutex::new(Bluetooth::new(tx.clone(), intf.clone())));
    let bluetooth_gatt = Arc::new(Mutex::new(BluetoothGatt::new(intf.clone())));

    topstack::get_runtime().block_on(async {
        // Connect to D-Bus system bus.
        let (resource, conn) = connection::new_system_sync()?;

        // The `resource` is a task that should be spawned onto a tokio compatible
        // reactor ASAP. If the resource ever finishes, we lost connection to D-Bus.
        topstack::get_runtime().spawn(async {
            let err = resource.await;
            panic!("Lost connection to D-Bus: {}", err);
        });

        // Request a service name and quit if not able to.
        conn.request_name(DBUS_SERVICE_NAME, false, true, false).await?;

        // Prepare D-Bus interfaces.
        let mut cr = Crossroads::new();
        cr.set_async_support(Some((
            conn.clone(),
            Box::new(|x| {
                topstack::get_runtime().spawn(x);
            }),
        )));

        intf.lock().unwrap().initialize(Arc::new(btif_bluetooth_callbacks(tx)), vec![]);

        // Run the stack main dispatch loop.
        topstack::get_runtime().spawn(Stack::dispatch(rx, bluetooth.clone()));

        // Set up the disconnect watcher to monitor client disconnects.
        let disconnect_watcher = Arc::new(Mutex::new(DisconnectWatcher::new()));
        disconnect_watcher.lock().unwrap().setup_watch(conn.clone()).await;

        // Register D-Bus method handlers of IBluetooth.
        iface_bluetooth::export_bluetooth_dbus_obj(
            OBJECT_BLUETOOTH,
            conn.clone(),
            &mut cr,
            bluetooth,
            disconnect_watcher.clone(),
        );
        // Register D-Bus method handlers of IBluetoothGatt.
        iface_bluetooth_gatt::export_bluetooth_gatt_dbus_obj(
            OBJECT_BLUETOOTH_GATT,
            conn.clone(),
            &mut cr,
            bluetooth_gatt,
            disconnect_watcher.clone(),
        );

        conn.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |msg, conn| {
                cr.handle_message(msg, conn).unwrap();
                true
            }),
        );

        // Serve clients forever.
        future::pending::<()>().await;
        unreachable!()
    })
}
