#! /bin/bash

# For bluetooth_packets_python3
PYTHONPATH=$PYTHONPATH:$ANDROID_BUILD_TOP/out/host/linux-x86/lib64 python3.8 `which act.py` -c $ANDROID_BUILD_TOP/system/bt/gd/l2cap/pts/pts.json -tf $ANDROID_BUILD_TOP/system/bt/gd/l2cap/pts/pts_l2cap_testcase -tp $ANDROID_BUILD_TOP/system/bt/gd
