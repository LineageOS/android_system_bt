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

class EventHandler:
    def __init__(self):
        self._handler_map = {}

    def on(self, matcher, func):
        self._handler_map[matcher] = func

    def execute(self, grpc_stream):
        for result in grpc_stream:
            for matcher, func in self._handler_map.items():
                if matcher(result):
                    func(result)

def is_connection_request(log):
    return log.HasField("connection_request")

def is_connection_response(log):
    return log.HasField("connection_response")

def is_configuration_request(log):
    return log.HasField("configuration_request")

def is_configuration_response(log):
    return log.HasField("configuration_response")

def is_disconnection_request(log):
    return log.HasField("disconnection_request")

def is_disconnection_response(log):
    return log.HasField("disconnection_response")

def is_echo_response(log):
    return log.HasField("echo_response")

def is_information_request(log):
    return log.HasField("information_request")

def is_information_response(log):
    return log.HasField("information_response")

def is_command_reject(log):
    return log.HasField("command_reject")

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

        log_event_handler = EventHandler()
        self.next_scid = 0x40
        self.scid_dcid_map = {}
        def handle_connection_request(log):
            log = log.connection_request
            self.cert_device.l2cap.SendConnectionResponse(l2cap_cert_pb2.ConnectionResponse(dcid=self.next_scid,scid=log.scid,
                                                                                            signal_id=log.signal_id))
            self.scid_dcid_map[self.next_scid] = log.scid
            self.next_scid += 1
            self.cert_device.l2cap.SendConfigurationRequest(l2cap_cert_pb2.ConfigurationRequest(dcid=log.scid,
                                                                                            signal_id=log.signal_id+1))
        log_event_handler.on(is_connection_request, handle_connection_request)

        def handle_connection_response(log):
            log = log.connection_response
            self.scid_dcid_map[log.scid] = log.dcid
            self.cert_device.l2cap.SendConfigurationRequest(l2cap_cert_pb2.ConfigurationRequest(dcid=log.dcid,
                                                                                              signal_id=log.signal_id+1))
        log_event_handler.on(is_connection_response, handle_connection_response)

        def handle_configuration_request(log):
            log = log.configuration_request
            if log.dcid not in self.scid_dcid_map:
                return
            dcid = self.scid_dcid_map[log.dcid]
            self.cert_device.l2cap.SendConfigurationResponse(l2cap_cert_pb2.ConfigurationResponse(scid=dcid,
                                                                                            signal_id=log.signal_id))
        log_event_handler.on(is_configuration_request, handle_configuration_request)

        def handle_disconnection_request(log):
            log = log.disconnection_request
            self.cert_device.l2cap.SendDisconnectionResponse(l2cap_cert_pb2.DisconnectionResponse(dcid=log.dcid,scid=log.scid,
                                                                                            signal_id=log.signal_id))
        log_event_handler.on(is_disconnection_request, handle_disconnection_request)

        def handle_information_request(log):
            log = log.information_request
            self.cert_device.l2cap.SendInformationResponse(l2cap_cert_pb2.InformationResponse(type=log.type,
                                                                                      signal_id=log.signal_id))
        log_event_handler.on(is_information_request, handle_information_request)

        self.event_dump = []
        def dump_log(log):
            self.event_dump.append(log)
        log_event_handler.on(lambda _: True, dump_log)
        self.event_handler = log_event_handler

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest()
        )
        self.cert_device.rootservice.StopStack(
            cert_rootservice_pb2.StopStackRequest()
        )

    def _setup_link(self):
        self.cert_device.l2cap.SetupLink(l2cap_cert_pb2.SetupLinkRequest(remote=self.dut_address))
        link_up_handled = []
        def handle_link_up(log):
            log = log.link_up
            link_up_handled.append(log.remote)
        self.event_handler.on(lambda log : log.HasField("link_up"), handle_link_up)
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        assert self.dut_address in link_up_handled

    def _open_channel(self, scid=0x0101, psm=0x01):
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(psm=psm))

        configuration_response_handled = []
        def handle_configuration_response(log):
            log = log.configuration_response
            configuration_response_handled.append(log.scid)
        self.event_handler.on(is_configuration_response, handle_configuration_response)
        self.cert_device.l2cap.SendConnectionRequest(l2cap_cert_pb2.ConnectionRequest(scid=scid, psm=psm))
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        assert scid in configuration_response_handled

    def test_connect(self):
        self._setup_link()
        self._open_channel(scid=0x0101)

    def test_connect_and_send_data(self):
        self.device_under_test.l2cap.RegisterChannel(l2cap_facade_pb2.RegisterChannelRequest(channel=2))
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(psm=0x01))
        self._setup_link()
        scid = 0x0101
        self._open_channel(scid=scid)
        self.device_under_test.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=2, payload=b"123"))

        data_received = []
        event_handler = EventHandler()
        def on_data_received(log):
            log = log.data_packet
            data_received.append((log.channel, log.payload))
        event_handler.on(lambda log : log.HasField("data_packet"), on_data_received)
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        event_handler.execute(logs)
        assert (2, b"123") in data_received

        self.device_under_test.l2cap.SendDynamicChannelPacket(l2cap_facade_pb2.DynamicChannelPacket(psm=1, payload=b'abc'))
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        event_handler.execute(logs)
        assert (scid, b"abc") in data_received

    def test_open_two_channels(self):
        self._setup_link()
        self._open_channel(scid=0x0101, psm=0x1)
        self._open_channel(scid=0x0102, psm=0x3)

    def test_accept_disconnect(self):
        """
        L2CAP/COS/CED/BV-07-C
        """
        self._setup_link()
        scid=0x0101
        self._open_channel(scid=scid, psm=0x1)
        dcid = self.scid_dcid_map[scid]
        disconnection_response_handled = []
        def handle_disconnection_response(log):
            log = log.disconnection_response
            disconnection_response_handled.append((log.scid, log.dcid))
        self.event_handler.on(is_disconnection_response, handle_disconnection_response)
        self.cert_device.l2cap.SendDisconnectionRequest(l2cap_cert_pb2.DisconnectionRequest(scid=scid, dcid=dcid, signal_id=2))
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        assert (scid, dcid) in disconnection_response_handled

    def test_disconnect_on_timeout(self):
        """
        L2CAP/COS/CED/BV-08-C
        """
        self._setup_link()
        scid = 0x0101
        psm = 1
        self._open_channel(scid=0x0101, psm=0x1)

        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(psm=psm))

        # Don't send configuration response back
        self.event_handler.on(is_configuration_request, lambda _: True)
        self.cert_device.l2cap.SendConnectionRequest(l2cap_cert_pb2.ConnectionRequest(scid=scid, psm=psm))
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        time.sleep(3)
        def handle_configuration_response(log):
            # DUT should not send configuration response due to timeout
            assert False
        self.event_handler.on(is_configuration_response, handle_configuration_response)
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)

    def test_basic_operation_request_connection(self):
        """
        L2CAP/COS/CED/BV-01-C [Request Connection]
        Verify that the IUT is able to request the connection establishment for an L2CAP data channel and
        initiate the configuration procedure.
        """
        psm = 1
        self.device_under_test.l2cap.OpenChannel(l2cap_facade_pb2.OpenChannelRequest(remote=self.cert_address, psm=psm))
        connection_request = []
        def handle_connection_request(log):
            log = log.connection_request
            connection_request.append(log.psm)
        self.event_handler.on(is_connection_request, handle_connection_request)
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        assert psm in connection_request

    def test_respond_to_echo_request(self):
        """
        L2CAP/COS/ECH/BV-01-C [Respond to Echo Request]
        Verify that the IUT responds to an echo request.
        """
        self._setup_link()
        # TODO: Replace with constructed packets when PDL is available
        echo_request_packet = b"\x08\x01\x00\x00"
        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=1, payload=echo_request_packet))
        echo_response = []
        def handle_echo_response(log):
            log = log.echo_response
            echo_response.append(log.signal_id)
        self.event_handler.on(is_echo_response, handle_echo_response)
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        assert 0x01 in echo_response

    def test_reject_unknown_command(self):
        """
        L2CAP/COS/CED/BI-01-C
        """
        self._setup_link()
        # TODO: Replace with constructed packets when PDL is available
        invalid_command_packet = b"\xff\x01\x00\x00"
        self.cert_device.l2cap.SendL2capPacket(l2cap_facade_pb2.L2capPacket(channel=1, payload=invalid_command_packet))
        command_reject_packet = b"\x01\x01\x02\x00\x00\x00"
        command_reject = []
        def handle_command_reject(log):
            log = log.command_reject
            command_reject.append(log.signal_id)
        self.event_handler.on(is_command_reject, handle_command_reject)
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        assert 0x01 in command_reject

    def test_query_for_1_2_features(self):
        """
        L2CAP/COS/IEX/BV-01-C [Query for 1.2 Features]
        """
        self._setup_link()
        signal_id = 3
        self.cert_device.l2cap.SendInformationRequest(
            l2cap_cert_pb2.InformationRequest(
                type=l2cap_cert_pb2.InformationRequestType.FIXED_CHANNELS, signal_id=signal_id))
        info_response = []
        def handle_info_response(log):
            log = log.information_response
            info_response.append((log.signal_id, log.type))
        self.event_handler.on(is_information_response, handle_info_response)
        logs = self.cert_device.l2cap.FetchL2capLog(l2cap_cert_pb2.FetchL2capLogRequest())
        self.event_handler.execute(logs)
        assert (signal_id, l2cap_cert_pb2.InformationRequestType.FIXED_CHANNELS) in info_response
