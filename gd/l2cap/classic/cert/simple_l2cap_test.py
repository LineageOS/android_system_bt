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
from cert import rootservice_pb2 as cert_rootservice_pb2
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from google.protobuf import empty_pb2
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from l2cap.classic.cert import api_pb2 as l2cap_cert_pb2

import time

class SimpleL2capTest(GdBaseTestClass):
    def setup_test(self):
        self.device_under_test = self.gd_devices[0]
        self.cert_device = self.gd_cert_devices[0]
        self.device_under_test.rootservice.StartStack(
            facade_rootservice_pb2.StartStackRequest(
                module_under_test=facade_rootservice_pb2.BluetoothModule.Value('L2CAP'),
            )
        )
        self.cert_device.rootservice.StartStack(
            cert_rootservice_pb2.StartStackRequest(
                module_to_test=cert_rootservice_pb2.BluetoothModule.Value('L2CAP'),
            )
        )

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

        dut_address = self.device_under_test.controller_read_only_property.ReadLocalAddress(empty_pb2.Empty()).address
        self.device_under_test.address = dut_address
        cert_address = self.cert_device.controller_read_only_property.ReadLocalAddress(empty_pb2.Empty()).address
        self.cert_device.address = cert_address

        self.dut_address = common_pb2.BluetoothAddress(
            address=self.device_under_test.address)
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert_device.address)

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest()
        )
        self.cert_device.rootservice.StopStack(
            cert_rootservice_pb2.StopStackRequest()
        )

    def test_connect_and_send_data(self):
        self.device_under_test.l2cap.RegisterChannel(l2cap_facade_pb2.RegisterChannelRequest(channel=2))
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(psm=0x01))
        dut_packet_stream = self.device_under_test.l2cap.packet_stream
        cert_packet_stream = self.cert_device.l2cap.packet_stream
        cert_connection_stream = self.cert_device.l2cap.connection_complete_stream
        dut_connection_stream = self.device_under_test.l2cap.connection_complete_stream
        cert_connection_stream.subscribe()
        dut_connection_stream.subscribe()
        self.device_under_test.l2cap.Connect(self.cert_address)
        cert_connection_stream.assert_event_occurs(
            lambda device: device.remote == self.dut_address
        )
        cert_connection_stream.unsubscribe()
        dut_connection_stream.assert_event_occurs(
            lambda device: device.remote == self.cert_address
        )
        dut_connection_stream.unsubscribe()

        self.cert_device.l2cap.SendConnectionRequest(l2cap_cert_pb2.ConnectionRequest())
        time.sleep(1)

        dut_packet_stream.subscribe()
        cert_packet_stream.subscribe()
        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=2, payload=b"abc"))
        dut_packet_stream.assert_event_occurs(
            lambda packet: b"abc" in packet.payload
        )
        self.device_under_test.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=2, payload=b"123"))
        cert_packet_stream.assert_event_occurs(
            lambda packet: b"123" in packet.payload
        )

        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=64, payload=b"123"))
        dut_packet_stream.assert_event_occurs(
            lambda packet: b"123" in packet.payload
        )

        self.device_under_test.l2cap.SendDynamicChannelPacket(l2cap_facade_pb2.DynamicChannelPacket(psm=1, payload=b'abc'))
        cert_packet_stream.assert_event_occurs(
            lambda packet: b"abc" in packet.payload
        )

        self.cert_device.l2cap.SendDisconnectionRequest(l2cap_cert_pb2.DisconnectionRequest())
        time.sleep(1)
        dut_packet_stream.unsubscribe()
        cert_packet_stream.unsubscribe()
