#!/usr/bin/env python3
#
#   Copyright 2019 - The Android Open Source Project
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from __future__ import print_function

import os
import sys
sys.path.append(os.environ['ANDROID_BUILD_TOP'] + '/system/bt/gd')

from cert.gd_base_test import GdBaseTestClass

from facade import common_pb2
from hal import facade_pb2 as hal_facade_pb2

class SimpleHalTest(GdBaseTestClass):
    def test_example(self):
        response = self.gd_devices[0].hal.SetLoopbackMode(hal_facade_pb2.LoopbackModeSettings(enable=True))
        print("Response " + str(response))

    def test_fetch_hci_event(self):
        response = self.gd_devices[0].hal.SetLoopbackMode(hal_facade_pb2.LoopbackModeSettings(enable=True))

        request = common_pb2.EventStreamRequest(subscription_mode=common_pb2.SUBSCRIBE,
                                                fetch_mode=common_pb2.NONE)
        response = self.gd_devices[0].hal.FetchHciEvent(request)

        inquiry_string = b'\x01\x04\x05\x33\x8b\x9e\x30\x01'
        response = self.gd_devices[0].hal.SendHciCommand(hal_facade_pb2.HciCommandPacket(payload=inquiry_string))

        request = common_pb2.EventStreamRequest(subscription_mode=common_pb2.UNCHANGED,
                                                fetch_mode=common_pb2.AT_LEAST_ONE)
        response = self.gd_devices[0].hal.FetchHciEvent(request)

        for event in response:
            print(event.payload)

        request = common_pb2.EventStreamRequest(subscription_mode=common_pb2.UNSUBSCRIBE,
                                                fetch_mode=common_pb2.NONE)
        response = self.gd_devices[0].hal.FetchHciEvent(request)
