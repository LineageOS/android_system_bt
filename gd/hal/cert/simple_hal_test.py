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
from hal import facade_pb2 as hal_facade_pb2

class SimpleHalTest(GdBaseTestClass):

    def test_fetch_hci_event(self):
        self.gd_devices[0].hal.SetLoopbackMode(
            hal_facade_pb2.LoopbackModeSettings(enable=True)
        )

        self.gd_devices[0].hal.hci_event_stream.subscribe()

        self.gd_devices[0].hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x01\x04\x053\x8b\x9e0\x01'
            )
        )
        self.gd_devices[0].hal.hci_event_stream.assert_event_occurs(
            lambda packet: packet.payload == b'\x19\x08\x01\x04\x053\x8b\x9e0\x01'
        )

        self.gd_devices[0].hal.hci_event_stream.unsubscribe()
