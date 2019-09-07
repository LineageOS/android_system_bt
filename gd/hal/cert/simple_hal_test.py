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
from cert.event_stream import EventStream
from cert import rootservice_pb2 as cert_rootservice_pb2
from facade import common_pb2
from google.protobuf import empty_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from hal.cert import api_pb2 as hal_cert_pb2
from hal import facade_pb2 as hal_facade_pb2

class SimpleHalTest(GdBaseTestClass):

    def setup_test(self):
        self.device_under_test = self.gd_devices[0]
        self.cert_device = self.gd_cert_devices[0]

        self.device_under_test.rootservice.StartStack(
            facade_rootservice_pb2.StartStackRequest(
                module_under_test=facade_rootservice_pb2.BluetoothModule.Value('HAL'),
            )
        )
        self.cert_device.rootservice.StartStack(
            cert_rootservice_pb2.StartStackRequest(
                module_to_test=cert_rootservice_pb2.BluetoothModule.Value('HAL'),
            )
        )

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

        self.device_under_test.hal.SendHciResetCommand(empty_pb2.Empty())
        self.cert_device.hal.SendHciResetCommand(empty_pb2.Empty())

        self.hci_event_stream = self.device_under_test.hal.hci_event_stream
        self.cert_hci_event_stream = self.cert_device.hal.hci_event_stream
        self.hci_acl_stream = self.device_under_test.hal.hci_acl_stream
        self.cert_hci_acl_stream = self.cert_device.hal.hci_acl_stream

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest()
        )
        self.cert_device.rootservice.StopStack(
            cert_rootservice_pb2.StopStackRequest()
        )
        self.hci_event_stream.clear_event_buffer()
        self.cert_hci_event_stream.clear_event_buffer()

    def test_none_event(self):
        self.hci_event_stream.clear_event_buffer()

        self.hci_event_stream.subscribe()
        self.hci_event_stream.assert_none()
        self.hci_event_stream.unsubscribe()

    def test_example(self):
        response = self.device_under_test.hal.SetLoopbackMode(
            hal_facade_pb2.LoopbackModeSettings(enable=True)
        )

    def test_fetch_hci_event(self):
        self.device_under_test.hal.SetLoopbackMode(
            hal_facade_pb2.LoopbackModeSettings(enable=True)
        )

        self.hci_event_stream.subscribe()

        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x01\x04\x053\x8b\x9e0\x01'
            )
        )

        self.hci_event_stream.assert_event_occurs(
            lambda packet: packet.payload == b'\x19\x08\x01\x04\x053\x8b\x9e0\x01'
        )
        self.hci_event_stream.unsubscribe()

    def test_inquiry_from_dut(self):
        self.hci_event_stream.subscribe()

        self.cert_device.hal.SetScanMode(
            hal_cert_pb2.ScanModeSettings(mode=3)
        )
        self.device_under_test.hal.SetInquiry(
            hal_facade_pb2.InquirySettings(length=0x30, num_responses=0xff)
        )
        self.hci_event_stream.assert_event_occurs(
            lambda packet: b'\x02\x0f' in packet.payload
            # Expecting an HCI Event (code 0x02, length 0x0f)
        )
        self.hci_event_stream.unsubscribe()

    def test_le_ad_scan_cert_advertises(self):
        self.hci_event_stream.subscribe()

        # Set the LE Address to 0D:05:04:03:02:01
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x05\x20\x06\x01\x02\x03\x04\x05\x0D'
            )
        )
        # Set the LE Scan parameters (active, 40ms, 20ms, Random, 
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x0B\x20\x07\x01\x40\x00\x20\x00\x01\x00'
            )
        )
        # Enable Scanning (Disable duplicate filtering)
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x0C\x20\x02\x01\x00'
            )
        )

        # Set the LE Address to 0C:05:04:03:02:01
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x05\x20\x06\x01\x02\x03\x04\x05\x0C'
            )
        )
        # Set LE Advertising parameters
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x06\x20\x0F\x00\x02\x00\x03\x00\x01\x00\xA1\xA2\xA3\xA4\xA5\xA6\x07\x00'
            )
        )
        # Set LE Advertising data
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x08\x20\x20\x0C\x0A\x09Im_A_Cert\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            )
        )
        # Enable Advertising
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x0A\x20\x01\x01'
            )
        )
        self.hci_event_stream.assert_event_occurs(
            lambda packet: b'Im_A_Cert' in packet.payload
            # Expecting an HCI Event (code 0x3e, length 0x13, subevent 0x01 )
        )
        # Disable Advertising
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x0A\x20\x01\x00'
            )
        )
        # Disable Scanning
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x0C\x20\x02\x00\x00'
            )
        )
        self.hci_event_stream.unsubscribe()

    def test_le_connection_dut_advertises(self):
        self.hci_event_stream.subscribe()
        self.cert_hci_event_stream.subscribe()
        self.hci_acl_stream.subscribe()
        self.cert_hci_acl_stream.subscribe()

        # Set the CERT LE Address to 0C:05:04:03:02:01
        self.cert_device.hal.SendHciCommand(
            hal_cert_pb2.HciCommandPacket(
                payload=b'\x05\x20\x06\x01\x02\x03\x04\x05\x0C'
            )
        )

        # Direct connect to 0D:05:04:03:02:01
        self.cert_device.hal.SendHciCommand(
            hal_cert_pb2.HciCommandPacket(
               payload=b'\x0D\x20\x19\x11\x01\x22\x02\x00\x01\x01\x02\x03\x04\x05\x0D\x01\x06\x00\x70\x0C\x40\x00\x03\x07\x01\x00\x02\x00'
            )
        )

        # Set the LE Address to 0D:05:04:03:02:01
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x05\x20\x06\x01\x02\x03\x04\x05\x0D'
            )
        )
        # Set LE Advertising parameters
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x06\x20\x0F\x80\x00\x00\x04\x00\x01\x00\xA1\xA2\xA3\xA4\xA5\xA6\x07\x00'
            )
        )
        # Set LE Advertising data
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x08\x20\x20\x0C\x0B\x09Im_The_DUT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            )
        )
        # Enable Advertising
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x0A\x20\x01\x01'
            )
        )
        # LeConnectionComplete TODO: Extract the handle
        self.cert_hci_event_stream.assert_event_occurs(
            lambda packet: b'\x3e\x13\x01\x00' in packet.payload
        )
        # LeConnectionComplete TODO: Extract the handle
        self.hci_event_stream.assert_event_occurs(
            lambda packet: b'\x3e\x13\x01\x00' in packet.payload
        )
        # Send ACL Data
        self.device_under_test.hal.SendHciAcl(
            hal_facade_pb2.HciAclPacket(
               payload=b'\xfe\x0e\x0b\x00SomeAclData'
            )
        )
        # Send ACL Data
        self.cert_device.hal.SendHciAcl(
            hal_facade_pb2.HciAclPacket(
               payload=b'\xfe\x0e\x0f\x00SomeMoreAclData'
            )
        )
        self.cert_hci_acl_stream.assert_event_occurs(
            lambda packet: b'\xfe\x0e\x0b\x00SomeAclData' in packet.payload
        )
        self.hci_acl_stream.assert_event_occurs(
            lambda packet: b'\xfe\x0e\x0f\x00SomeMoreAclData' in packet.payload
        )

        self.hci_event_stream.unsubscribe()
        self.cert_hci_event_stream.unsubscribe()
        self.hci_acl_stream.unsubscribe()
        self.cert_hci_acl_stream.unsubscribe()

    def test_le_white_list_connection_cert_advertises(self):
        self.hci_event_stream.subscribe()
        self.cert_hci_event_stream.subscribe()

        # Set the LE Address to 0D:05:04:03:02:01
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x05\x20\x06\x01\x02\x03\x04\x05\x0D'
            )
        )
        # Add the cert device to the white list (Random 0C:05:04:03:02:01)
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x11\x20\x07\x01\x01\x02\x03\x04\x05\x0C'
            )
        )
        # Connect using the white list
        self.device_under_test.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x0D\x20\x19\x11\x01\x22\x02\x01\x00\xA1\xA2\xA3\xA4\xA5\xA6\x01\x06\x00\x70\x0C\x40\x00\x03\x07\x01\x00\x02\x00'
            )
        )

        # Set the LE Address to 0C:05:04:03:02:01
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
                payload=b'\x05\x20\x06\x01\x02\x03\x04\x05\x0C'
            )
        )
        # Set LE Advertising parameters
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x06\x20\x0F\x00\x02\x00\x03\x00\x01\x00\xA1\xA2\xA3\xA4\xA5\xA6\x07\x00'
            )
        )
        # Set LE Advertising data
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x08\x20\x20\x0C\x0A\x09Im_A_Cert\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            )
        )
        # Enable Advertising
        self.cert_device.hal.SendHciCommand(
            hal_facade_pb2.HciCommandPacket(
               payload=b'\x0A\x20\x01\x01'
            )
        )
        # LeConnectionComplete
        self.cert_hci_event_stream.assert_event_occurs(
            lambda packet: b'\x3e\x13\x01\x00' in packet.payload
        )
        # LeConnectionComplete
        self.hci_event_stream.assert_event_occurs(
            lambda packet: b'\x3e\x13\x01\x00' in packet.payload
        )

        self.hci_event_stream.unsubscribe()
        self.cert_hci_event_stream.unsubscribe()
