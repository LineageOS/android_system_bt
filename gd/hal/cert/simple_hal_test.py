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
import time
sys.path.append(os.environ['ANDROID_BUILD_TOP'] + '/system/bt/gd')

from cert.gd_base_test import GdBaseTestClass
from cert.event_stream import EventStream
from facade import common_pb2
from google.protobuf import empty_pb2

from hal.cert import api_pb2 as hal_cert_pb2
from hal import facade_pb2 as hal_facade_pb2

class SimpleHalTest(GdBaseTestClass):

    def setup_test(self):
        self.device_under_test = self.gd_devices[0]
        self.cert_device = self.gd_cert_devices[0]

        self.device_under_test.hal.SendHciResetCommand(empty_pb2.Empty())
        self.cert_device.hal.SendHciResetCommand(empty_pb2.Empty())

    def test_none_event(self):
        self.device_under_test.hal.hci_event_stream.clear_event_buffer()

        self.device_under_test.hal.hci_event_stream.subscribe()
        self.device_under_test.hal.hci_event_stream.assert_none()
        self.device_under_test.hal.hci_event_stream.unsubscribe()

    def test_example(self):
        response = self.device_under_test.hal.SetLoopbackMode(
            hal_facade_pb2.LoopbackModeSettings(enable=True)
        )

    def test_fetch_hci_event(self):
        self.device_under_test.hal.SetLoopbackMode(
            hal_facade_pb2.LoopbackModeSettings(enable=True)
        )

        self.device_under_test.hal.hci_event_stream.subscribe()

        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x01\x04\x053\x8b\x9e0\x01'
            )
        )

        self.device_under_test.hal.hci_event_stream.assert_event_occurs(
            lambda packet: packet.payload == b'\x19\x08\x01\x04\x053\x8b\x9e0\x01'
        )
        self.device_under_test.hal.hci_event_stream.unsubscribe()

    def test_inquiry_from_dut(self):
        self.device_under_test.hal.hci_event_stream.subscribe()

        self.cert_device.hal.SetScanMode(
            hal_cert_pb2.ScanModeSettings(mode=3)
        )
        self.device_under_test.hal.SetInquiry(
            hal_facade_pb2.InquirySettings(length=0x30, num_responses=0xff)
        )
        self.device_under_test.hal.hci_event_stream.assert_event_occurs(
            lambda packet: b'\x02\x0f' in packet.payload
            # Expecting an HCI Event (code 0x02, length 0x0f)
        )
        self.device_under_test.hal.hci_event_stream.unsubscribe()
