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
from cert.event_asserts import EventAsserts
from cert.event_callback_stream import EventCallbackStream
from cert import rootservice_pb2 as cert_rootservice_pb2
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from google.protobuf import empty_pb2
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from l2cap.classic.cert import api_pb2 as l2cap_cert_pb2

ASYNC_OP_TIME_SECONDS = 1  # TODO: Use events to synchronize events instead


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


def basic_frame_to_enhanced_information_frame(information_payload):
    return information_payload[2:]


class SimpleL2capTest(GdBaseTestClass):

    def setup_test(self):
        self.device_under_test = self.gd_devices[0]
        self.cert_device = self.gd_cert_devices[0]
        self.device_under_test.rootservice.StartStack(
            facade_rootservice_pb2.StartStackRequest(
                module_under_test=facade_rootservice_pb2.BluetoothModule.Value(
                    'L2CAP'),))
        self.cert_device.rootservice.StartStack(
            cert_rootservice_pb2.StartStackRequest(
                module_to_test=cert_rootservice_pb2.BluetoothModule.Value(
                    'L2CAP'),))

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

        dut_address = self.device_under_test.controller_read_only_property.ReadLocalAddress(
            empty_pb2.Empty()).address
        self.device_under_test.address = dut_address
        cert_address = self.cert_device.controller_read_only_property.ReadLocalAddress(
            empty_pb2.Empty()).address
        self.cert_device.address = cert_address

        self.dut_address = common_pb2.BluetoothAddress(
            address=self.device_under_test.address)
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert_device.address)

        self.next_scid = 0x40
        self.scid_dcid_map = {}
        self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.BASIC

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest())
        self.cert_device.rootservice.StopStack(
            cert_rootservice_pb2.StopStackRequest())

    def _register_callbacks(self, event_callback_stream):

        def handle_connection_request(log):
            log = log.connection_request
            self.cert_device.l2cap.SendConnectionResponse(
                l2cap_cert_pb2.ConnectionResponse(
                    dcid=self.next_scid, scid=log.scid,
                    signal_id=log.signal_id))
            self.scid_dcid_map[self.next_scid] = log.scid
            self.next_scid += 1
            self.cert_device.l2cap.SendConfigurationRequest(
                l2cap_cert_pb2.ConfigurationRequest(
                    dcid=log.scid,
                    signal_id=log.signal_id + 1,
                    retransmission_config=l2cap_cert_pb2.
                    ChannelRetransmissionFlowControlConfig(
                        mode=self.retransmission_mode)))

        self.handle_connection_request = handle_connection_request
        event_callback_stream.register_callback(
            self.handle_connection_request, matcher_fn=is_connection_request)

        def handle_connection_response(log):
            log = log.connection_response
            self.scid_dcid_map[log.scid] = log.dcid
            self.cert_device.l2cap.SendConfigurationRequest(
                l2cap_cert_pb2.ConfigurationRequest(
                    dcid=log.dcid,
                    signal_id=log.signal_id + 1,
                    retransmission_config=l2cap_cert_pb2.
                    ChannelRetransmissionFlowControlConfig(
                        mode=self.retransmission_mode)))

        self.handle_connection_request = handle_connection_request
        event_callback_stream.register_callback(
            self.handle_connection_response, matcher_fn=is_connection_response)

        def handle_configuration_request(log):
            log = log.configuration_request
            if log.dcid not in self.scid_dcid_map:
                return
            dcid = self.scid_dcid_map[log.dcid]
            self.cert_device.l2cap.SendConfigurationResponse(
                l2cap_cert_pb2.ConfigurationResponse(
                    scid=dcid,
                    signal_id=log.signal_id,
                    retransmission_config=l2cap_cert_pb2.
                    ChannelRetransmissionFlowControlConfig(
                        mode=self.retransmission_mode)))

        self.handle_configuration_request = handle_configuration_request
        event_callback_stream.register_callback(
            self.handle_configuration_request,
            matcher_fn=is_configuration_request)

        def handle_disconnection_request(log):
            log = log.disconnection_request
            self.cert_device.l2cap.SendDisconnectionResponse(
                l2cap_cert_pb2.DisconnectionResponse(
                    dcid=log.dcid, scid=log.scid, signal_id=log.signal_id))

        self.handle_disconnection_request = handle_disconnection_request
        event_callback_stream.register_callback(
            self.handle_disconnection_request,
            matcher_fn=is_disconnection_request)

        def handle_information_request(log):
            log = log.information_request
            self.cert_device.l2cap.SendInformationResponse(
                l2cap_cert_pb2.InformationResponse(
                    type=log.type, signal_id=log.signal_id))

        self.handle_information_request = handle_information_request
        event_callback_stream.register_callback(
            self.handle_information_request, matcher_fn=is_information_request)

        self.event_dump = []

        def dump_log(log):
            self.event_dump.append(log)

        self.dump_log = dump_log
        event_callback_stream.register_callback(self.dump_log)

    def _setup_link(self, event_asserts):
        self.cert_device.l2cap.SetupLink(
            l2cap_cert_pb2.SetupLinkRequest(remote=self.dut_address))
        event_asserts.assert_event_occurs(
            lambda log: log.HasField("link_up") and log.remote == self.dut_address
        )

    def _open_channel(self, event_asserts, scid=0x0101, psm=0x33):
        self.device_under_test.l2cap.SetDynamicChannel(
            l2cap_facade_pb2.SetEnableDynamicChannelRequest(psm=psm))
        self.cert_device.l2cap.SendConnectionRequest(
            l2cap_cert_pb2.ConnectionRequest(scid=scid, psm=psm))
        event_asserts.assert_event_occurs(
            lambda log: is_configuration_response(log) and scid == log.scid)

    def test_connect(self):
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            self._open_channel(l2cap_event_asserts, scid=0x0101)

    def test_connect_and_send_data_ertm_no_segmentation(self):
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            self.device_under_test.l2cap.RegisterChannel(
                l2cap_facade_pb2.RegisterChannelRequest(channel=2))
            self.device_under_test.l2cap.SetDynamicChannel(
                l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                    psm=0x33,
                    retransmission_mode=l2cap_facade_pb2.
                    RetransmissionFlowControlMode.ERTM))

            self._setup_link(l2cap_event_asserts)
            scid = 0x0101
            self._open_channel(l2cap_event_asserts, scid=scid)

            def on_data_received(log):
                packet = log.data_packet
                if (packet.channel == scid):
                    self.cert_device.l2cap.SendSFrame(
                        l2cap_cert_pb2.SFrame(
                            channel=self.scid_dcid_map[scid], req_seq=1, s=0))

            l2cap_log_stream.register_callback(
                on_data_received,
                matcher_fn=lambda log: log.HasField("data_packet"))

            self.device_under_test.l2cap.SendL2capPacket(
                l2cap_facade_pb2.L2capPacket(channel=2, payload=b"123"))
            l2cap_event_asserts.assert_event_occurs(
                lambda log : log.HasField("data_packet") and \
                             log.data_packet.channel == 2 and \
                             basic_frame_to_enhanced_information_frame(log.data_packet.payload) == b"123")

            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(
                    psm=0x33, payload=b'abc' * 34))
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=1,
                    tx_seq=0,
                    sar=0,
                    information=b"abcd"))
            l2cap_event_asserts.assert_event_occurs(
                lambda log : log.HasField("data_packet") and \
                             log.data_packet.channel == scid and \
                             basic_frame_to_enhanced_information_frame(log.data_packet.payload) == b"abc"*34)

    def test_connect_and_send_data(self):
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            self.device_under_test.l2cap.RegisterChannel(
                l2cap_facade_pb2.RegisterChannelRequest(channel=2))
            self.device_under_test.l2cap.SetDynamicChannel(
                l2cap_facade_pb2.SetEnableDynamicChannelRequest(psm=0x33))

            self._setup_link(l2cap_event_asserts)
            scid = 0x0101
            self._open_channel(l2cap_event_asserts, scid=scid)

            self.device_under_test.l2cap.SendL2capPacket(
                l2cap_facade_pb2.L2capPacket(channel=2, payload=b"123"))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == 2 and log.data_packet.payload == b"123"
            )

            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == scid and log.data_packet.payload == b"abc"
            )

    def test_open_two_channels(self):
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            self._open_channel(l2cap_event_asserts, scid=0x0101, psm=0x1)
            self._open_channel(l2cap_event_asserts, scid=0x0102, psm=0x3)

    def test_accept_disconnect(self):
        """
        L2CAP/COS/CED/BV-07-C
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            scid = 0x0101
            self._open_channel(l2cap_event_asserts, scid=scid, psm=0x1)
            dcid = self.scid_dcid_map[scid]
            self.cert_device.l2cap.SendDisconnectionRequest(
                l2cap_cert_pb2.DisconnectionRequest(
                    scid=scid, dcid=dcid, signal_id=2))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: is_disconnection_response(log) and log.disconnection_response.scid == scid and log.disconnection_response.dcid == dcid
            )

    def test_disconnect_on_timeout(self):
        """
        L2CAP/COS/CED/BV-08-C
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            scid = 0x0101
            psm = 1
            self._open_channel(l2cap_event_asserts, scid=0x0101, psm=0x1)

            self.device_under_test.l2cap.SetDynamicChannel(
                l2cap_facade_pb2.SetEnableDynamicChannelRequest(psm=psm))

            # Don't send configuration response back
            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.cert_device.l2cap.SendConnectionRequest(
                l2cap_cert_pb2.ConnectionRequest(scid=scid, psm=psm))
            l2cap_event_asserts.assert_none_matching(is_configuration_response)

    def test_basic_operation_request_connection(self):
        """
        L2CAP/COS/CED/BV-01-C [Request Connection]
        Verify that the IUT is able to request the connection establishment for an L2CAP data channel and
        initiate the configuration procedure.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            psm = 1
            # TODO: Use another test case
            self.device_under_test.l2cap.OpenChannel(
                l2cap_facade_pb2.OpenChannelRequest(
                    remote=self.cert_address, psm=psm))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: is_connection_request(log) and log.connection_request.psm == psm
            )

    def test_respond_to_echo_request(self):
        """
        L2CAP/COS/ECH/BV-01-C [Respond to Echo Request]
        Verify that the IUT responds to an echo request.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            # TODO: Replace with constructed packets when PDL is available
            echo_request_packet = b"\x08\x01\x00\x00"
            self.cert_device.l2cap.SendL2capPacket(
                l2cap_facade_pb2.L2capPacket(
                    channel=1, payload=echo_request_packet))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: is_echo_response(log) and log.echo_response.signal_id == 0x01
            )

    def test_reject_unknown_command(self):
        """
        L2CAP/COS/CED/BI-01-C
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            # TODO: Replace with constructed packets when PDL is available
            invalid_command_packet = b"\xff\x01\x00\x00"
            self.cert_device.l2cap.SendL2capPacket(
                l2cap_facade_pb2.L2capPacket(
                    channel=1, payload=invalid_command_packet))
            # command_reject_packet = b"\x01\x01\x02\x00\x00\x00"
            l2cap_event_asserts.assert_event_occurs(
                lambda log: is_command_reject(log) and log.command_reject.signal_id == 0x01
            )

    def test_query_for_1_2_features(self):
        """
        L2CAP/COS/IEX/BV-01-C [Query for 1.2 Features]
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            signal_id = 3
            self.cert_device.l2cap.SendInformationRequest(
                l2cap_cert_pb2.InformationRequest(
                    type=l2cap_cert_pb2.InformationRequestType.FIXED_CHANNELS,
                    signal_id=signal_id))
            l2cap_event_asserts.assert_event_occurs(
                lambda log : is_information_response(log) and \
                             log.information_response.signal_id == signal_id and \
                             log.information_response.type == l2cap_cert_pb2.InformationRequestType.FIXED_CHANNELS)

    def test_extended_feature_info_response_ertm(self):
        """
        L2CAP/EXF/BV-01-C [Extended Features Information Response for Enhanced
        Retransmission Mode]
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)

            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            signal_id = 3
            self.cert_device.l2cap.SendInformationRequest(
                l2cap_cert_pb2.InformationRequest(
                    type=l2cap_cert_pb2.InformationRequestType.
                    EXTENDED_FEATURES,
                    signal_id=signal_id))

            l2cap_event_asserts_alt.assert_event_occurs_at_most_times(
                is_information_response, 1)

            expected_log_type = l2cap_cert_pb2.InformationRequestType.EXTENDED_FEATURES
            expected_mask = 1 << 3
            l2cap_event_asserts.assert_event_occurs(
                lambda log : is_information_response(log) and \
                    log.information_response.signal_id == signal_id and \
                    log.information_response.type == expected_log_type and \
                    log.information_response.information_value | expected_mask == expected_mask)

    def test_transmit_i_frames(self):
        """
        L2CAP/ERM/BV-01-C [Transmit I-frames]
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            self.device_under_test.l2cap.RegisterChannel(
                l2cap_facade_pb2.RegisterChannelRequest(channel=2))
            self.device_under_test.l2cap.SetDynamicChannel(
                l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                    psm=0x33,
                    retransmission_mode=l2cap_facade_pb2.
                    RetransmissionFlowControlMode.ERTM))
            self._setup_link(l2cap_event_asserts)
            scid = 0x0101
            self._open_channel(l2cap_event_asserts, scid=scid)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=1, s=0))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=2, s=0))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=3, s=0))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == 33 and log.data_packet.payload == b'abc'
            )
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == 33 and log.data_packet.payload == b'abc'
            )
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == 33 and log.data_packet.payload == b'abc'
            )
            l2cap_event_asserts_alt.assert_event_occurs_at_most(
                lambda log: log.HasField("data_packet"), 3)

    def test_s_frame_transmissions_exceed_max_transmit(self):
        """
        L2CAP/ERM/BV-11-C [S-Frame Transmissions Exceed MaxTransmit]
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            self.device_under_test.l2cap.RegisterChannel(
                l2cap_facade_pb2.RegisterChannelRequest(channel=2))
            self.device_under_test.l2cap.SetDynamicChannel(
                l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                    psm=0x33,
                    retransmission_mode=l2cap_facade_pb2.
                    RetransmissionFlowControlMode.ERTM))
            self._setup_link(l2cap_event_asserts)
            scid = 0x0101
            self._open_channel(l2cap_event_asserts, scid=scid)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            # Retransmission timer = 1, 1 * monitor timer = 2, so total timeout is 3
            time.sleep(4)
            l2cap_event_asserts.assert_event_occurs(lambda log : is_disconnection_request(log) and \
                                                        log.disconnection_request.dcid == scid and \
                                                        log.disconnection_request.scid == self.scid_dcid_map[scid])
            l2cap_event_asserts_alt.assert_event_occurs_at_most(
                lambda log: is_disconnection_request(log), 1)

    def test_sent_rej_lost(self):
        """
        L2CAP/ERM/BI-01-C [S-Frame [REJ] Lost or Corrupted]
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)

            signal_id = 3
            scid = 0x0101
            psm = 1
            mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            self.tx_window = 1
            self.device_under_test.l2cap.SetDynamicChannel(
                l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                    psm=psm, retransmission_mode=mode))
            self.cert_device.l2cap.SendConnectionRequest(
                l2cap_cert_pb2.ConnectionRequest(scid=scid, psm=psm))

            l2cap_log_stream.unregister_callback(
                self.handle_Connection_response,
                matcher_fn=is_configuration_response)

            def handle_connection_response(log):
                log = log.connection_response
                self.scid_dcid_map[log.scid] = log.dcid
                self.cert_device.l2cap.SendConfigurationRequest(
                    l2cap_cert_pb2.ConfigurationRequest(
                        dcid=self.scid_dcid_map[scid],
                        signal_id=signal_id + 1,
                        retransmission_config=l2cap_cert_pb2.
                        ChannelRetransmissionFlowControlConfig(mode=mode)))
                l2cap_log_stream.unregister_callback(
                    handle_connection_response,
                    matcher_fn=is_connection_response)

            l2cap_log_stream.register_callback(
                handle_connection_response, matcher_fn=is_connection_response)

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)

            def handle_configuration_request(log):
                log = log.configuration_request
                if log.dcid not in self.scid_dcid_map:
                    return
                dcid = self.scid_dcid_map[log.dcid]
                if log.HasField("retransmission_config"):
                    self.tx_window = log.retransmission_config.tx_window
                self.cert_device.l2cap.SendConfigurationResponse(
                    l2cap_cert_pb2.ConfigurationResponse(
                        scid=dcid,
                        signal_id=log.signal_id,
                    ))
                l2cap_log_stream.unregister_callback(
                    handle_configuration_request,
                    matcher_fn=is_configuration_request)

            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=0,
                    sar=0))
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=(self.tx_window - 1),
                    sar=0))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == scid and log.data_packet.payload == b'\x05\x01'
            )

            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=0, p=1, s=0))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == scid and log.data_packet.payload == b'\x81\x01'
            )

            for i in range(1, self.tx_window):
                self.cert_device.l2cap.SendIFrame(
                    l2cap_cert_pb2.IFrame(
                        channel=self.scid_dcid_map[scid],
                        req_seq=0,
                        tx_seq=(i),
                        sar=0))
                time.sleep(0.1)
            l2cap_event_asserts.assert_event_occurs(
                lambda log: log.HasField("data_packet") and log.data_packet.channel == scid and log.data_packet.payload == b'\x01\x0a'
            )
