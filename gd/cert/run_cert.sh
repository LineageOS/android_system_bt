#! /bin/bash

# For bluetooth_packets_python3

# Run normal facade to cert API tests
PYTHONPATH=$PYTHONPATH:$ANDROID_BUILD_TOP/out/host/linux-x86/lib64 python3.8 `which act.py` -c $ANDROID_BUILD_TOP/system/bt/gd/cert/host_only_config.json -tf $ANDROID_BUILD_TOP/system/bt/gd/cert/cert_testcases -tp $ANDROID_BUILD_TOP/system/bt/gd

# Run new facade to facade API tests
PYTHONPATH=$PYTHONPATH:$ANDROID_BUILD_TOP/out/host/linux-x86/lib64 python3.8 `which act.py` -c $ANDROID_BUILD_TOP/system/bt/gd/cert/host_only_config_facade_only.json -tf $ANDROID_BUILD_TOP/system/bt/gd/cert/cert_testcases_facade_only -tp $ANDROID_BUILD_TOP/system/bt/gd