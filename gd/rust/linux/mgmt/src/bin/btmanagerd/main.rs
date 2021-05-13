mod state_machine;

use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus_crossroads::Crossroads;
use dbus_tokio::connection;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let context = state_machine::start_new_state_machine_context();
    let proxy = context.get_proxy();

    // Connect to the D-Bus system bus (this is blocking, unfortunately).
    let (resource, c) = connection::new_system_sync()?;

    // The resource is a task that should be spawned onto a tokio compatible
    // reactor ASAP. If the resource ever finishes, you lost connection to D-Bus.
    tokio::spawn(async {
        let err = resource.await;
        panic!("Lost connection to D-Bus: {}", err);
    });

    // Let's request a name on the bus, so that clients can find us.
    c.request_name("org.chromium.bluetooth.Manager", false, true, false).await?;

    // Create a new crossroads instance.
    // The instance is configured so that introspection and properties interfaces
    // are added by default on object path additions.
    let mut cr = Crossroads::new();

    // Enable async support for the crossroads instance.
    cr.set_async_support(Some((
        c.clone(),
        Box::new(|x| {
            tokio::spawn(x);
        }),
    )));

    let iface_token = cr.register("org.chromium.bluetooth.Manager", |b| {
        b.method_with_cr_async(
            "Start",
            ("hci_interface",),
            (),
            |mut ctx, cr, (hci_interface,): (i32,)| {
                let proxy =
                    cr.data_mut::<state_machine::StateMachineProxy>(ctx.path()).unwrap().clone();
                println!("Incoming Start call for hci {}!", hci_interface);
                async move {
                    let result = proxy.start_bluetooth(hci_interface).await;
                    match result {
                        Ok(()) => ctx.reply(Ok(())),
                        Err(_) => ctx.reply(Err(dbus_crossroads::MethodErr::failed(
                            "cannot start Bluetooth",
                        ))),
                    }
                }
            },
        );
        b.method_with_cr_async("Stop", ("hci_interface",), (), |mut ctx, cr, (hci_interface,) : (i32,)| {
            let proxy =
                cr.data_mut::<state_machine::StateMachineProxy>(ctx.path()).unwrap().clone();
            println!("Incoming Stop call!");
            async move {
                let result = proxy.stop_bluetooth(hci_interface).await;
                match result {
                    Ok(()) => ctx.reply(Ok(())),
                    Err(_) => {
                        ctx.reply(Err(dbus_crossroads::MethodErr::failed("cannot stop Bluetooth")))
                    }
                }
            }
        });
        b.method_with_cr_async("GetState", (), ("result",), |mut ctx, cr, ()| {
            let proxy =
                cr.data_mut::<state_machine::StateMachineProxy>(ctx.path()).unwrap().clone();
            async move {
                let state = proxy.get_state().await;
                let result = match state {
                    state_machine::State::Off => 0,
                    state_machine::State::TurningOn => 1,
                    state_machine::State::On => 2,
                    state_machine::State::TurningOff => 3,
                };
                ctx.reply(Ok((result,)))
            }
        });
        b.method_with_cr_async(
            "RegisterStateChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let proxy =
                    cr.data_mut::<state_machine::StateMachineProxy>(ctx.path()).unwrap().clone();
                async move {
                    let result = proxy.register_state_change_observer(object_path.clone()).await;
                    match result {
                        Ok(()) => ctx.reply(Ok(())),
                        Err(_) => ctx.reply(Err(dbus_crossroads::MethodErr::failed(&format!(
                            "cannot register {}",
                            object_path
                        )))),
                    }
                }
            },
        );
        b.method_with_cr_async(
            "UnregisterStateChangeObserver",
            ("object_path",),
            (),
            |mut ctx, cr, (object_path,): (String,)| {
                let proxy =
                    cr.data_mut::<state_machine::StateMachineProxy>(ctx.path()).unwrap().clone();
                async move {
                    let result = proxy.unregister_state_change_observer(object_path.clone()).await;
                    match result {
                        Ok(()) => ctx.reply(Ok(())),
                        Err(_) => ctx.reply(Err(dbus_crossroads::MethodErr::failed(&format!(
                            "cannot unregister {}",
                            object_path
                        )))),
                    }
                }
            },
        );
    });

    // Let's add the "/org/chromium/bluetooth/Manager" path, which implements the org.chromium.bluetooth.Manager interface,
    // to the crossroads instance.
    cr.insert("/org/chromium/bluetooth/Manager", &[iface_token], proxy);

    // We add the Crossroads instance to the connection so that incoming method calls will be handled.
    c.start_receive(
        MatchRule::new_method_call(),
        Box::new(move |msg, conn| {
            cr.handle_message(msg, conn).unwrap();
            true
        }),
    );

    tokio::spawn(async move {
        state_machine::mainloop(context).await;
    });

    loop {}

    // Run forever.
    unreachable!()
}
