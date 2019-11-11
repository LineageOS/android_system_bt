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

ASYNC_OP_TIME_SECONDS = 1  # TODO: Use events to synchronize events instead

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

        self.cert_device.l2cap.SendConnectionRequest(l2cap_cert_pb2.ConnectionRequest(scid=0x101, psm=1))
        time.sleep(ASYNC_OP_TIME_SECONDS)
        open_channels = self.cert_device.l2cap.FetchOpenedChannels(l2cap_cert_pb2.FetchOpenedChannelsRequest())
        cid = open_channels.dcid[0]
        self.cert_device.l2cap.SendConfigurationRequest(l2cap_cert_pb2.ConfigurationRequest(scid=cid))
        time.sleep(ASYNC_OP_TIME_SECONDS)

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

        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=cid, payload=b"123"))
        dut_packet_stream.assert_event_occurs(
            lambda packet: b"123" in packet.payload
        )

        self.device_under_test.l2cap.SendDynamicChannelPacket(l2cap_facade_pb2.DynamicChannelPacket(psm=1, payload=b'abc'))
        cert_packet_stream.assert_event_occurs(
            lambda packet: b"abc" in packet.payload
        )

        self.cert_device.l2cap.SendDisconnectionRequest(l2cap_cert_pb2.DisconnectionRequest(dcid=0x40, scid=101))
        time.sleep(ASYNC_OP_TIME_SECONDS)
        dut_packet_stream.unsubscribe()
        cert_packet_stream.unsubscribe()

    def test_open_two_channels(self):
        cert_connection_stream = self.cert_device.l2cap.connection_complete_stream
        cert_connection_stream.subscribe()
        self.device_under_test.l2cap.OpenChannel(l2cap_facade_pb2.OpenChannelRequest(remote=self.cert_address, psm=0x01))
        self.device_under_test.l2cap.OpenChannel(l2cap_facade_pb2.OpenChannelRequest(remote=self.cert_address, psm=0x03))
        cert_connection_stream.assert_event_occurs(
            lambda device: device.remote == self.dut_address
        )
        cert_connection_stream.unsubscribe()
        time.sleep(ASYNC_OP_TIME_SECONDS)
        open_channels = self.cert_device.l2cap.FetchOpenedChannels(l2cap_cert_pb2.FetchOpenedChannelsRequest())
        assert len(open_channels.dcid) == 2

    def test_accept_disconnect(self):
        """
        L2CAP/COS/CED/BV-07-C
        """
        self.device_under_test.l2cap.OpenChannel(l2cap_facade_pb2.OpenChannelRequest(remote=self.cert_address, psm=0x01))
        cert_connection_stream = self.cert_device.l2cap.connection_complete_stream
        cert_connection_stream.subscribe()
        self.device_under_test.l2cap.Connect(self.cert_address)
        cert_connection_stream.assert_event_occurs(
            lambda device: device.remote == self.dut_address
        )
        cert_connection_stream.unsubscribe()
        time.sleep(ASYNC_OP_TIME_SECONDS)
        cert_packet_stream = self.cert_device.l2cap.packet_stream
        cert_packet_stream.subscribe()
        open_channels = self.cert_device.l2cap.FetchOpenedChannels(l2cap_cert_pb2.FetchOpenedChannelsRequest())
        cid = open_channels.dcid[0]
        disconnection_request_packet = b"\x06\x01\x04\x00\x40\x00\x40\x01"
        disconnection_response_packet = b"\x07\x01\x04\x00\x40\x00\x40\x01"
        #TODO(b/143374372): Instead of hardcoding this, use packet builder
        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=1, payload=disconnection_request_packet))
        cert_packet_stream.assert_event_occurs(
            lambda packet: disconnection_response_packet in packet.payload
        )
        cert_packet_stream.unsubscribe()
        time.sleep(ASYNC_OP_TIME_SECONDS)  # TODO(b/144186649): Remove this line

    def test_basic_operation_request_connection(self):
        """
        L2CAP/COS/CED/BV-01-C [Request Connection]
        Verify that the IUT is able to request the connection establishment for an L2CAP data channel and
        initiate the configuration procedure.
        """
        cert_connection_stream = self.cert_device.l2cap.connection_complete_stream
        cert_connection_stream.subscribe()
        self.device_under_test.l2cap.OpenChannel(l2cap_facade_pb2.OpenChannelRequest(remote=self.cert_address, psm=0x01))
        cert_connection_stream.assert_event_occurs(
            lambda device: device.remote == self.dut_address
        )
        cert_connection_stream.unsubscribe()

    def test_respond_to_echo_request(self):
        """
        L2CAP/COS/ECH/BV-01-C [Respond to Echo Request]
        Verify that the IUT responds to an echo request.
        """
        self.device_under_test.l2cap.RegisterChannel(l2cap_facade_pb2.RegisterChannelRequest(channel=2))
        cert_connection_stream = self.cert_device.l2cap.connection_complete_stream
        cert_connection_stream.subscribe()
        self.device_under_test.l2cap.Connect(self.cert_address)
        cert_connection_stream.assert_event_occurs(
            lambda device: device.remote == self.dut_address
        )
        cert_connection_stream.unsubscribe()
        cert_packet_stream = self.cert_device.l2cap.packet_stream
        cert_packet_stream.subscribe()
        echo_request_packet = b"\x08\x01\x00\x00"
        echo_response_packet = b"\x09\x01\x00\x00"
        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=1, payload=echo_request_packet))
        cert_packet_stream.assert_event_occurs(
            lambda packet: echo_response_packet in packet.payload
        )
        cert_packet_stream.unsubscribe()
        time.sleep(ASYNC_OP_TIME_SECONDS)  # TODO(b/144186649): Remove this line

    def test_reject_unknown_command(self):
        """
        L2CAP/COS/CED/BI-01-C
        """
        cert_connection_stream = self.cert_device.l2cap.connection_complete_stream
        cert_connection_stream.subscribe()
        self.device_under_test.l2cap.RegisterChannel(l2cap_facade_pb2.RegisterChannelRequest(channel=2))
        self.device_under_test.l2cap.Connect(self.cert_address)
        cert_connection_stream.assert_event_occurs(
            lambda device: device.remote == self.dut_address
        )
        cert_connection_stream.unsubscribe()
        cert_packet_stream = self.cert_device.l2cap.packet_stream
        cert_packet_stream.subscribe()
        invalid_command_packet = b"\xff\x01\x00\x00"
        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=1, payload=invalid_command_packet))
        command_reject_packet = b"\x01\x01\x02\x00\x00\x00"
        cert_packet_stream.assert_event_occurs(
            lambda packet: command_reject_packet in packet.payload
        )
        cert_packet_stream.unsubscribe()

        time.sleep(ASYNC_OP_TIME_SECONDS)  # TODO(b/144186649): Remove this line
