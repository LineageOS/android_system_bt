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

import os
import sys
import time
from datetime import timedelta

from cert.gd_base_test import GdBaseTestClass
from cert.event_asserts import EventAsserts
from cert.event_callback_stream import EventCallbackStream
from cert import rootservice_pb2 as cert_rootservice_pb2
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from google.protobuf import empty_pb2
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from l2cap.classic.cert import api_pb2 as l2cap_cert_pb2
from hci.facade import controller_facade_pb2 as controller_facade
from neighbor.facade import facade_pb2 as neighbor_facade

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


def get_enhanced_control_field(payload):
    return payload[:2]


def match_frame(log, scid, control_field=None, payload=None):
    if not log.HasField("data_packet"):
        return False
    if log.data_packet.channel != scid:
        return False
    frame = log.data_packet.payload
    if frame == None:
        return False
    if control_field and \
        get_enhanced_control_field(frame) != control_field:
        return False
    if payload and \
        basic_frame_to_enhanced_information_frame(frame) != payload:
        return False
    return True


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

        self.device_under_test.address = self.device_under_test.hci_controller.GetMacAddress(
            empty_pb2.Empty()).address
        self.cert_device.address = self.cert_device.controller_read_only_property.ReadLocalAddress(
            empty_pb2.Empty()).address
        self.dut_address = common_pb2.BluetoothAddress(
            address=self.device_under_test.address)
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert_device.address)

        self.device_under_test.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))

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

        self.handle_connection_response = handle_connection_response
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
            lambda log: log.HasField("link_up") and log.link_up.remote == self.dut_address
        )

    def _open_channel(
            self,
            event_asserts,
            scid=0x0101,
            psm=0x33,
            mode=l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.BASIC):
        self.device_under_test.l2cap.SetDynamicChannel(
            l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                psm=psm, retransmission_mode=mode))
        self.cert_device.l2cap.SendConnectionRequest(
            l2cap_cert_pb2.ConnectionRequest(scid=scid, psm=psm))
        event_asserts.assert_event_occurs(
            lambda log: is_configuration_response(log) and scid == log.configuration_response.scid
        )

        # Allow some time for channel creation on facade side after configuration response is received.
        time.sleep(0.5)

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
                             log.data_packet.payload == b"123")

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

            l2cap_event_asserts_alt.assert_event_occurs_at_most(
                is_information_response, 1)

            expected_log_type = l2cap_cert_pb2.InformationRequestType.EXTENDED_FEATURES
            expected_mask = 1 << 3
            l2cap_event_asserts.assert_event_occurs(
                lambda log : is_information_response(log) and \
                    log.information_response.signal_id == signal_id and \
                    log.information_response.type == expected_log_type and \
                    log.information_response.information_value & expected_mask == expected_mask)

    def test_extended_feature_info_response_fcs(self):
        """
        L2CAP/EXF/BV-03-C [Extended Features Information Response for FCS Option]
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

            l2cap_event_asserts_alt.assert_event_occurs_at_most(
                is_information_response, 1)

            expected_log_type = l2cap_cert_pb2.InformationRequestType.EXTENDED_FEATURES
            expected_mask = 1 << 5
            l2cap_event_asserts.assert_event_occurs(
                lambda log : is_information_response(log) and \
                    log.information_response.signal_id == signal_id and \
                    log.information_response.type == expected_log_type and \
                    log.information_response.information_value & expected_mask == expected_mask)

    def test_config_channel_not_use_FCS(self):
        """
        L2CAP/FOC/BV-01-C [IUT Initiated Configuration of the FCS Option]
        Verify the IUT can configure a channel to not use FCS in I/S-frames.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x00\x00', payload=b'abc'))

    def test_explicitly_request_use_FCS(self):
        """
        L2CAP/FOC/BV-02-C [Lower Tester Explicitly Requests FCS should be Used]
        Verify the IUT will include the FCS in I/S-frames if the Lower Tester explicitly requests that FCS
        should be used.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            information_value = 1 << 3 | 1 << 5

            def handle_information_request(log):
                log = log.information_request
                self.cert_device.l2cap.SendInformationResponse(
                    l2cap_cert_pb2.InformationResponse(
                        type=log.type,
                        signal_id=log.signal_id,
                        information_value=information_value))

            l2cap_log_stream.unregister_callback(
                self.handle_information_request,
                matcher_fn=is_information_request)
            l2cap_log_stream.register_callback(
                handle_information_request, matcher_fn=is_information_request)

            def handle_connection_response(log):
                log = log.connection_response
                self.scid_dcid_map[log.scid] = log.dcid

            l2cap_log_stream.unregister_callback(
                self.handle_connection_response,
                matcher_fn=is_connection_response)
            l2cap_log_stream.register_callback(
                handle_connection_response, matcher_fn=is_connection_response)

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
                self.cert_device.l2cap.SendConfigurationRequest(
                    l2cap_cert_pb2.ConfigurationRequest(
                        dcid=dcid,
                        signal_id=log.signal_id + 1,
                        retransmission_config=l2cap_cert_pb2.
                        ChannelRetransmissionFlowControlConfig(
                            mode=self.retransmission_mode),
                        fcs_config=l2cap_cert_pb2.FcsConfig.DEFAULT))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            l2cap_event_asserts_alt.assert_event_occurs(
                lambda log: is_configuration_request(log) and \
                    log.configuration_request.fcs_config == l2cap_cert_pb2.FcsConfig.NO_FCS)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, payload=b'abc\x0f\xb6'))

    def test_implicitly_request_use_FCS(self):
        """
        L2CAP/FOC/BV-03-C [Lower Tester Implicitly Requests FCS should be Used]
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x41
            psm = 0x41
            information_value = 1 << 3 | 1 << 5

            def handle_information_request(log):
                log = log.information_request
                self.cert_device.l2cap.SendInformationResponse(
                    l2cap_cert_pb2.InformationResponse(
                        type=log.type,
                        signal_id=log.signal_id,
                        information_value=information_value))

            l2cap_log_stream.unregister_callback(
                self.handle_information_request,
                matcher_fn=is_information_request)
            l2cap_log_stream.register_callback(
                handle_information_request, matcher_fn=is_information_request)

            def handle_connection_response(log):
                log = log.connection_response
                self.scid_dcid_map[log.scid] = log.dcid

            l2cap_log_stream.unregister_callback(
                self.handle_connection_response,
                matcher_fn=is_connection_response)
            l2cap_log_stream.register_callback(
                handle_connection_response, matcher_fn=is_connection_response)

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
                self.cert_device.l2cap.SendConfigurationRequest(
                    l2cap_cert_pb2.ConfigurationRequest(
                        dcid=dcid,
                        signal_id=log.signal_id + 1,
                        retransmission_config=l2cap_cert_pb2.
                        ChannelRetransmissionFlowControlConfig(
                            mode=self.retransmission_mode),
                        fcs_config=l2cap_cert_pb2.FcsConfig.NON))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts,
                scid=scid,
                psm=psm,
                mode=self.retransmission_mode)
            l2cap_event_asserts_alt.assert_event_occurs(
                lambda log: is_configuration_request(log) and \
                    log.configuration_request.fcs_config == l2cap_cert_pb2.FcsConfig.NO_FCS)
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], p=1, withFcs=True))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x81\x00', payload=b'\x75\xe8'))

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
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
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
                lambda log: match_frame(log, scid=scid, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, payload=b'abc'))
            l2cap_event_asserts_alt.assert_event_occurs_at_most(
                lambda log: log.HasField("data_packet"), 3)

    def test_receive_i_frames(self):
        """
        L2CAP/ERM/BV-02-C [Receive I-Frames]
        Verify the IUT can receive in-sequence valid I-frames and deliver L2CAP SDUs to the Upper Tester
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            for i in range(3):
                self.cert_device.l2cap.SendIFrame(
                    l2cap_cert_pb2.IFrame(
                        channel=self.scid_dcid_map[scid],
                        req_seq=0,
                        tx_seq=i,
                        sar=0))
                l2cap_event_asserts.assert_event_occurs(
                        lambda log :log.HasField("data_packet") and \
                        log.data_packet.channel == scid and \
                        log.data_packet.payload[1] == i + 1
                    )
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=3,
                    sar=1,
                    information=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                    lambda log :log.HasField("data_packet") and \
                    log.data_packet.channel == scid and \
                    log.data_packet.payload[1] == 4
                )
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=4,
                    sar=3,
                    information=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                    lambda log :log.HasField("data_packet") and \
                    log.data_packet.channel == scid and \
                    log.data_packet.payload[1] == 5
                )
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=5,
                    sar=2,
                    information=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                    lambda log :log.HasField("data_packet") and \
                    log.data_packet.channel == scid and \
                    log.data_packet.payload[1] == 6
                )

    def test_acknowledging_received_i_frames(self):
        """
        L2CAP/ERM/BV-03-C [Acknowledging Received I-Frames]
        Verify the IUT sends S-frame [RR] with the Poll bit not set to acknowledge data received from the
        Lower Tester
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            for i in range(3):
                self.cert_device.l2cap.SendIFrame(
                    l2cap_cert_pb2.IFrame(
                        channel=self.scid_dcid_map[scid],
                        req_seq=0,
                        tx_seq=i,
                        sar=0))
                l2cap_event_asserts.assert_event_occurs(
                    lambda log: log.HasField("data_packet") and \
                        log.data_packet.channel == scid and \
                        log.data_packet.payload[1] == i + 1
                )

            l2cap_event_asserts_alt.assert_event_occurs_at_most(
                lambda log: log.HasField("data_packet"), 3)

    def test_resume_transmitting_when_received_rr(self):
        """
        L2CAP/ERM/BV-05-C [Resume Transmitting I-Frames when an S-Frame [RR] is Received]
        Verify the IUT will cease transmission of I-frames when the negotiated TxWindow is full. Verify the
        IUT will resume transmission of I-frames when an S-frame [RR] is received that acknowledges
        previously sent I-frames.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_connection_response(log):
                log = log.connection_response
                self.scid_dcid_map[log.scid] = log.dcid
                self.cert_device.l2cap.SendConfigurationRequest(
                    l2cap_cert_pb2.ConfigurationRequest(
                        dcid=log.dcid,
                        signal_id=log.signal_id + 1,
                        retransmission_config=l2cap_cert_pb2.
                        ChannelRetransmissionFlowControlConfig(
                            mode=self.retransmission_mode, tx_window=1)))

            l2cap_log_stream.unregister_callback(
                self.handle_connection_response,
                matcher_fn=is_connection_response)
            l2cap_log_stream.register_callback(
                handle_connection_response, matcher_fn=is_connection_response)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            psm = 0x33
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs_at_most(
                lambda log: match_frame(log, scid=scid, payload=b'abc'),
                1,
                timeout=timedelta(seconds=0.5))
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=1, s=0))
            l2cap_event_asserts.assert_event_occurs_at_most(
                lambda log: match_frame(log, scid=scid, payload=b'abc'),
                1,
                timeout=timedelta(seconds=0.5))

    def test_resume_transmitting_when_acknowledge_previously_sent(self):
        """
        L2CAP/ERM/BV-06-C [Resume Transmitting I-Frames when an I-Frame is Received]
        Verify the IUT will cease transmission of I-frames when the negotiated TxWindow is full. Verify the
        IUT will resume transmission of I-frames when an I-frame is received that acknowledges previously
        sent I-frames.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_connection_response(log):
                log = log.connection_response
                self.scid_dcid_map[log.scid] = log.dcid
                self.cert_device.l2cap.SendConfigurationRequest(
                    l2cap_cert_pb2.ConfigurationRequest(
                        dcid=log.dcid,
                        signal_id=log.signal_id + 1,
                        retransmission_config=l2cap_cert_pb2.
                        ChannelRetransmissionFlowControlConfig(
                            mode=self.retransmission_mode, tx_window=1)))

            l2cap_log_stream.unregister_callback(
                self.handle_connection_response,
                matcher_fn=is_connection_response)
            l2cap_log_stream.register_callback(
                handle_connection_response, matcher_fn=is_connection_response)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            psm = 0x33
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))

            l2cap_event_asserts.assert_event_occurs_at_most(
                lambda log: match_frame(log, scid=scid, payload=b'abc'),
                1,
                timeout=timedelta(seconds=0.5))
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=1,
                    tx_seq=0,
                    sar=0))
            l2cap_event_asserts.assert_event_occurs_at_most(
                lambda log: match_frame(log, scid=scid, payload=b'abc'),
                1,
                timeout=timedelta(seconds=0.5))
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=2, s=0))

    def test_transmit_s_frame_rr_with_poll_bit_set(self):
        """
        L2CAP/ERM/BV-08-C [Send S-Frame [RR] with Poll Bit Set]
        Verify the IUT sends an S-frame [RR] with the Poll bit set when its retransmission timer expires.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            time.sleep(1)
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'))

    def test_transmit_s_frame_rr_with_final_bit_set(self):
        """
        L2CAP/ERM/BV-09-C [Send S-Frame [RR] with Final Bit Set]
        Verify the IUT responds with an S-frame [RR] with the Final bit set after receiving an S-frame [RR]
        with the Poll bit set.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=0, s=0, p=1))

            l2cap_event_asserts.assert_event_occurs(
                    lambda log: match_frame(log, scid=scid, control_field=b'\x81\x00'))

    def test_s_frame_transmissions_exceed_max_transmit(self):
        """
        L2CAP/ERM/BV-11-C [S-Frame Transmissions Exceed MaxTransmit]
        Verify the IUT will close the channel when the Monitor Timer expires.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            psm = 0x33
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            # Retransmission timer = 1, 1 * monitor timer = 2, so total timeout is 3
            time.sleep(4)
            l2cap_event_asserts.assert_event_occurs(
                    lambda log : is_disconnection_request(log) and \
                        log.disconnection_request.dcid == scid and \
                        log.disconnection_request.scid == self.scid_dcid_map[scid])
            l2cap_event_asserts_alt.assert_event_occurs_at_most(
                lambda log: is_disconnection_request(log), 1)

    def test_i_frame_transmissions_exceed_max_transmit(self):
        """
        L2CAP/ERM/BV-12-C [I-Frame Transmissions Exceed MaxTransmit]
        Verify the IUT will close the channel when it receives an S-frame [RR] with the final bit set that does
        not acknowledge the previous I-frame sent by the IUT.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            l2cap_event_asserts_alt = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            psm = 0x33
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'))

            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=0, p=0, s=0, f=1))
            l2cap_event_asserts.assert_none_matching(
                lambda log: log.HasField("data_packet"))
            l2cap_event_asserts_alt.assert_event_occurs(
                lambda log : is_disconnection_request(log) and \
                    log.disconnection_request.dcid == scid and \
                    log.disconnection_request.scid == self.scid_dcid_map[scid])

    def test_respond_to_rej(self):
        """
        L2CAP/ERM/BV-13-C [Respond to S-Frame [REJ]]
        Verify the IUT retransmits I-frames starting from the sequence number specified in the S-frame [REJ].
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_connection_response(log):
                log = log.connection_response
                self.scid_dcid_map[log.scid] = log.dcid
                self.cert_device.l2cap.SendConfigurationRequest(
                    l2cap_cert_pb2.ConfigurationRequest(
                        dcid=log.dcid,
                        signal_id=log.signal_id + 1,
                        retransmission_config=l2cap_cert_pb2.
                        ChannelRetransmissionFlowControlConfig(
                            mode=self.retransmission_mode,
                            tx_window=2,
                            max_transmit=2)))

            l2cap_log_stream.unregister_callback(
                self.handle_connection_response,
                matcher_fn=is_connection_response)
            l2cap_log_stream.register_callback(
                handle_connection_response, matcher_fn=is_connection_response)

            def handle_configuration_request(log):
                log = log.configuration_request
                if log.dcid not in self.scid_dcid_map:
                    return
                dcid = self.scid_dcid_map[log.dcid]
                self.cert_device.l2cap.SendConfigurationResponse(
                    l2cap_cert_pb2.ConfigurationResponse(
                        scid=dcid,
                        signal_id=log.signal_id,
                        retransmission_config=log.retransmission_config))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            psm = 0x33
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            for i in range(2):
                l2cap_event_asserts.assert_event_occurs(
                    lambda log: match_frame(log, scid=scid, payload=b'abc'),
                    timeout=timedelta(seconds=0.5))

            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(channel=self.scid_dcid_map[scid], s=1))

            for i in range(2):
                l2cap_event_asserts.assert_event_occurs(
                    lambda log: match_frame(log, scid=scid, payload=b'abc'),
                    timeout=timedelta(seconds=0.5))

    def test_receive_s_frame_rr_final_bit_set(self):
        """
        L2CAP/ERM/BV-18-C [Receive S-Frame [RR] Final Bit = 1]
        Verify the IUT will retransmit any previously sent I-frames unacknowledged by receipt of an S-Frame
        [RR] with the Final Bit set.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_configuration_request(log):
                log = log.configuration_request
                if log.dcid not in self.scid_dcid_map:
                    return
                dcid = self.scid_dcid_map[log.dcid]
                self.cert_device.l2cap.SendConfigurationResponse(
                    l2cap_cert_pb2.ConfigurationResponse(
                        scid=dcid,
                        signal_id=log.signal_id,
                        retransmission_config=log.retransmission_config))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            time.sleep(1)
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'))

            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=0, p=0, s=0, f=1))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x00\x00', payload=b'abc'))

    def test_receive_i_frame_final_bit_set(self):
        """
        L2CAP/ERM/BV-19-C [Receive I-Frame Final Bit = 1]
        Verify the IUT will retransmit any previously sent I-frames unacknowledged by receipt of an I-frame
        with the final bit set.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_configuration_request(log):
                log = log.configuration_request
                if log.dcid not in self.scid_dcid_map:
                    return
                dcid = self.scid_dcid_map[log.dcid]
                self.cert_device.l2cap.SendConfigurationResponse(
                    l2cap_cert_pb2.ConfigurationResponse(
                        scid=dcid,
                        signal_id=log.signal_id,
                        retransmission_config=log.retransmission_config))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            time.sleep(1)
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'))
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=0,
                    sar=0,
                    f=1))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x00\x00', payload=b'abc') or \
                    match_frame(log, scid=scid, control_field=b'\x00\x01', payload=b'abc'))

    def test_recieve_rnr(self):
        """
        L2CAP/ERM/BV-20-C [Enter Remote Busy Condition]
        Verify the IUT will not retransmit any I-frames when it receives a remote busy indication from the
        Lower Tester (S-frame [RNR]).
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            time.sleep(1)
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'))

            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=0, p=0, s=2, f=1))
            l2cap_event_asserts.assert_none_matching(
                lambda log: match_frame(log, scid=scid, control_field=b'\x00\x00', payload=b'abc'))

    def test_sent_rej_lost(self):
        """
        L2CAP/ERM/BI-01-C [S-Frame [REJ] Lost or Corrupted]
        Verify the IUT can handle receipt of an S-=frame [RR] Poll = 1 if the S-frame [REJ] sent from the IUT
        is lost.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)

            self._register_callbacks(l2cap_log_stream)
            signal_id = 3
            scid = 0x0101
            tx_window = 5
            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM

            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)

            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=0,
                    sar=0,
                    information=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                    lambda log: match_frame(log, scid=scid, control_field=b'\x01\x01'))
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=(tx_window - 1),
                    sar=0,
                    information=b'def'))
            l2cap_event_asserts.assert_event_occurs(
                    lambda log: match_frame(log, scid=scid, control_field=b'\x05\x01'))
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], req_seq=0, p=1, s=0))
            l2cap_event_asserts.assert_event_occurs(
                    lambda log: match_frame(log, scid=scid, control_field=b'\x81\x01'))
            for i in range(1, tx_window):
                self.cert_device.l2cap.SendIFrame(
                    l2cap_cert_pb2.IFrame(
                        channel=self.scid_dcid_map[scid],
                        req_seq=0,
                        tx_seq=(i),
                        sar=0))
                l2cap_event_asserts.assert_event_occurs(
                        lambda log :log.HasField("data_packet") and \
                        log.data_packet.channel == scid and \
                        log.data_packet.payload[1] == i + 1
                    )

    def test_handle_duplicate_srej(self):
        """
        L2CAP/ERM/BI-03-C [Handle Duplicate S-Frame [SREJ]]
        Verify the IUT will only retransmit the requested I-frame once after receiving a duplicate SREJ.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_configuration_request(log):
                log = log.configuration_request
                if log.dcid not in self.scid_dcid_map:
                    return
                dcid = self.scid_dcid_map[log.dcid]
                self.cert_device.l2cap.SendConfigurationResponse(
                    l2cap_cert_pb2.ConfigurationResponse(
                        scid=dcid,
                        signal_id=log.signal_id,
                        retransmission_config=log.retransmission_config))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'), timeout=timedelta(seconds=2))

            # Send SREJ with F not set
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(channel=self.scid_dcid_map[scid], s=3))
            l2cap_event_asserts.assert_none(timeout=timedelta(seconds=0.5))
            # Send SREJ with F set
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], s=3, f=1))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x00\x00', payload=b'abc'))

    def test_handle_receipt_rej_and_rr_with_f_set(self):
        """
        L2CAP/ERM/BI-04-C [Handle Receipt of S-Frame [REJ] and S-Frame [RR, F=1] that Both Require Retransmission of the Same I-Frames]
        Verify the IUT will only retransmit the requested I-frames once after receiving an S-frame [REJ]
        followed by an S-frame [RR] with the Final bit set that indicates the same I-frames should be
        retransmitted.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_configuration_request(log):
                log = log.configuration_request
                if log.dcid not in self.scid_dcid_map:
                    return
                dcid = self.scid_dcid_map[log.dcid]
                self.cert_device.l2cap.SendConfigurationResponse(
                    l2cap_cert_pb2.ConfigurationResponse(
                        scid=dcid,
                        signal_id=log.signal_id,
                        retransmission_config=log.retransmission_config))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            psm = 0x33
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, payload=b'abc'),
                timeout=timedelta(seconds=0.5))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, payload=b'abc'),
                timeout=timedelta(seconds=0.5))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'), timeout=timedelta(seconds=2))

            # Send REJ with F not set
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(channel=self.scid_dcid_map[scid], s=1))
            l2cap_event_asserts.assert_none(timeout=timedelta(seconds=0.5))
            # Send RR with F set
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(
                    channel=self.scid_dcid_map[scid], s=0, f=1))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x00\x00', payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x02\x00', payload=b'abc'))

    def test_handle_rej_and_i_frame_with_f_set(self):
        """
        L2CAP/ERM/BI-05-C [Handle receipt of S-Frame [REJ] and I-Frame [F=1] that Both Require Retransmission of the Same I-Frames]
        Verify the IUT will only retransmit the requested I-frames once after receiving an S-frame [REJ]
        followed by an I-frame with the Final bit set that indicates the same I-frames should be retransmitted.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)

            def handle_configuration_request(log):
                log = log.configuration_request
                if log.dcid not in self.scid_dcid_map:
                    return
                dcid = self.scid_dcid_map[log.dcid]
                self.cert_device.l2cap.SendConfigurationResponse(
                    l2cap_cert_pb2.ConfigurationResponse(
                        scid=dcid,
                        signal_id=log.signal_id,
                        retransmission_config=log.retransmission_config))

            l2cap_log_stream.unregister_callback(
                self.handle_configuration_request,
                matcher_fn=is_configuration_request)
            l2cap_log_stream.register_callback(
                handle_configuration_request,
                matcher_fn=is_configuration_request)

            self.retransmission_mode = l2cap_cert_pb2.ChannelRetransmissionFlowControlMode.ERTM
            scid = 0x0101
            psm = 0x33
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, mode=self.retransmission_mode)
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            for i in range(2):
                l2cap_event_asserts.assert_event_occurs(
                    lambda log: match_frame(log, scid=scid, payload=b'abc'),
                    timeout=timedelta(seconds=0.5))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x11\x00'), timeout=timedelta(seconds=2))

            # Send SREJ with F not set
            self.cert_device.l2cap.SendSFrame(
                l2cap_cert_pb2.SFrame(channel=self.scid_dcid_map[scid], s=3))
            l2cap_event_asserts.assert_none(timeout=timedelta(seconds=0.5))
            self.cert_device.l2cap.SendIFrame(
                l2cap_cert_pb2.IFrame(
                    channel=self.scid_dcid_map[scid],
                    req_seq=0,
                    tx_seq=0,
                    sar=0,
                    f=1))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x00\x01', payload=b'abc'))
            l2cap_event_asserts.assert_event_occurs(
                lambda log: match_frame(log, scid=scid, control_field=b'\x02\x01', payload=b'abc'))

    def test_initiated_configurtion_request_ertm(self):
        """
        L2CAP/CMC/BV-01-C [IUT Initiated Configuration of Enhanced Retransmission Mode]
        Verify the IUT can send a Configuration Request command containing the F&EC option that specifies
        Enhanced Retransmission Mode.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            psm = 1
            scid = 0x0101
            self.retransmission_mode = l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)
            self._open_channel(
                l2cap_event_asserts, scid=scid, mode=self.retransmission_mode)

            l2cap_event_asserts.assert_event_occurs(
                lambda log: is_configuration_request(log) and \
                    log.configuration_request.dcid == scid and\
                    log.configuration_request.retransmission_config.mode == self.retransmission_mode
                )

    def test_respond_configuration_request_ertm(self):
        """
        L2CAP/CMC/BV-02-C [Lower Tester Initiated Configuration of Enhanced Retransmission Mode]
        Verify the IUT can accept a Configuration Request from the Lower Tester containing an F&EC option
        that specifies Enhanced Retransmission Mode.
        """
        with EventCallbackStream(
                self.cert_device.l2cap.FetchL2capLog(
                    empty_pb2.Empty())) as l2cap_log_stream:
            l2cap_event_asserts = EventAsserts(l2cap_log_stream)
            self._register_callbacks(l2cap_log_stream)
            self._setup_link(l2cap_event_asserts)

            psm = 1
            scid = 0x0101
            self.retransmission_mode = l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM
            self.device_under_test.l2cap.SetDynamicChannel(
                l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                    psm=psm, retransmission_mode=self.retransmission_mode))
            self.cert_device.l2cap.SendConnectionRequest(
                l2cap_cert_pb2.ConnectionRequest(scid=scid, psm=psm))

            l2cap_event_asserts.assert_event_occurs(
                lambda log: is_configuration_response(log) and \
                    log.configuration_response.scid == scid and\
                    log.configuration_response.result == l2cap_cert_pb2.ConfigurationResult.SUCCESS and \
                    log.configuration_response.retransmission_config.mode == self.retransmission_mode)
