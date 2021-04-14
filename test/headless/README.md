##
## bluetooth headless
##
## A device-side executable that consists of a binary executable
## driving the Android libbluetooth libraries.
##

Requirements:
    1. Android installation,
    2. Root access to adb connected Android device.

Build: Source, lunch and build as typical Android target for selected device and architecture.
    cd $ANDROID_BUILD_TOP
    . build/envsetup.sh && lunch <target>
    make bt_headless

Install: Push the binary to an executable area on target device.
    adb push out/target/product/<device..arch>/bt_headless/bt_headless /data/data/.

Prepare: Ensure the system is queisced to prevent resource conflicts from the bluetooth process.
    adb shell stop

Run: Script or directly execute the target file.
    adb shell /data/data/bt_headless --flags=INIT_logging_debug_enabled_for_all=true,INIT_gd_acl=true nop
