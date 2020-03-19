#! /bin/bash

source $ANDROID_BUILD_TOP/system/bt/cert/run \
  --test_config=$ANDROID_BUILD_TOP/system/bt/gd/cert/pts.json \
  --test_file=$ANDROID_BUILD_TOP/system/bt/gd/cert/pts_l2cap_testcase