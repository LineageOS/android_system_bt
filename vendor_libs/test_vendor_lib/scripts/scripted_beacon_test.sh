
#$ANDROID_BUILD_TOP/out/host/linux-x86/bin/root-canal &
sleep 1
python3 scripts/test_channel.py 6401 < scripts/scripted_beacon_test_add_beacon
python3 scripts/hci_socket.py 6402 < scripts/scripted_beacon_test_start_scan
sleep 30
