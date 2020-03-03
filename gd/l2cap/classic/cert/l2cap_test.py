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

import time
from datetime import timedelta
from mobly import asserts

from cert.gd_base_test_facade_only import GdFacadeOnlyBaseTestClass
from cert.event_stream import EventStream
from cert.truth import assertThat
from cert.closable import safeClose
from cert.py_l2cap import PyL2cap
from cert.py_acl_manager import PyAclManager
from cert.matchers import L2capMatchers
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice
from google.protobuf import empty_pb2 as empty_proto
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from neighbor.facade import facade_pb2 as neighbor_facade
from hci.facade import acl_manager_facade_pb2 as acl_manager_facade
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import hci_packets, l2cap_packets
from bluetooth_packets_python3.l2cap_packets import CommandCode
from cert_l2cap import CertL2cap

# Assemble a sample packet. TODO: Use RawBuilder
SAMPLE_PACKET = l2cap_packets.CommandRejectNotUnderstoodBuilder(1)


class L2capTest(GdFacadeOnlyBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='L2CAP', cert_module='HCI_INTERFACES')

    def setup_test(self):
        super().setup_test()

        self.dut.address = self.dut.hci_controller.GetMacAddress(
            empty_proto.Empty()).address
        cert_address = self.cert.controller_read_only_property.ReadLocalAddress(
            empty_proto.Empty()).address
        self.cert.address = cert_address
        self.dut_address = common_pb2.BluetoothAddress(address=self.dut.address)
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert.address)

        self.dut.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))

        self.dut_l2cap = PyL2cap(self.dut)
        self.cert_l2cap = CertL2cap(self.cert)
        self.cert_acl = None

    def teardown_test(self):
        self.cert_l2cap.close()
        super().teardown_test()

    def cert_send_b_frame(self, b_frame):
        self.cert_acl.send(b_frame.Serialize())

    def _setup_link_from_cert(self):

        self.dut.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))
        self.cert_l2cap.connect_acl(self.dut.address)
        self.cert_acl = self.cert_l2cap.get_acl()

    def _open_channel(
            self,
            signal_id=1,
            scid=0x0101,
            psm=0x33,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC):

        self.dut_channel = self.dut_l2cap.open_channel(psm, mode)
        self.cert_channel = self.cert_l2cap.open_channel(signal_id, psm, scid)

    def test_connect_dynamic_channel_and_send_data(self):
        self._setup_link_from_cert()

        self._open_channel(signal_id=1, scid=0x41, psm=0x33)

        self.dut_channel.send(b'abc')
        assertThat(
            self.cert_channel).emits(lambda packet: b'abc' in packet.payload)

    def test_fixed_channel(self):
        self._setup_link_from_cert()

        self.dut.l2cap.RegisterChannel(
            l2cap_facade_pb2.RegisterChannelRequest(channel=2))
        asserts.skip("FIXME: Not working")
        self.dut.l2cap.SendL2capPacket(
            l2cap_facade_pb2.L2capPacket(channel=2, payload=b"123"))

        assertThat(
            self.cert_channel).emits(lambda packet: b'123' in packet.payload)

    def test_receive_packet_from_unknown_channel(self):
        self._setup_link_from_cert()
        psm = 0x33
        scid = 0x41
        self._open_channel(1, scid, psm)

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            0x99, 0, l2cap_packets.Final.NOT_SET, 1,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_l2cap.send_acl(i_frame)
        assertThat(self.cert_l2cap.get_acl_stream()).emitsNone(
            L2capMatchers.SupervisoryFrame(scid, req_seq=4),
            timeout=timedelta(seconds=1))

    def test_open_two_channels(self):
        self._setup_link_from_cert()

        self._open_channel(1, 0x41, 0x41)
        self._open_channel(2, 0x43, 0x43)

    def test_connect_and_send_data_ertm_no_segmentation(self):
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut_channel.send(b'abc' * 34)
        assertThat(self.cert_channel).emits(
            lambda packet: b'abc' * 34 in packet.payload)

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 0, l2cap_packets.Final.NOT_SET, 1,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

    def test_basic_operation_request_connection(self):
        """
        L2CAP/COS/CED/BV-01-C [Request Connection]
        Verify that the IUT is able to request the connection establishment for an L2CAP data channel and
        initiate the configuration procedure.
        """
        self._setup_link_from_cert()

        psm = 0x33
        # TODO: Use another test case
        self.dut.l2cap.OpenChannel(
            l2cap_facade_pb2.OpenChannelRequest(
                remote=self.cert_address, psm=psm))
        assertThat(self.cert_acl).emits(L2capMatchers.ConnectionRequest())

    def test_accept_disconnect(self):
        """
        L2CAP/COS/CED/BV-07-C
        """
        self._setup_link_from_cert()

        scid = 0x41
        psm = 0x33
        self._open_channel(1, scid, psm)

        dcid = self.cert_l2cap.get_dcid(scid)

        close_channel = l2cap_packets.DisconnectionRequestBuilder(1, dcid, scid)
        close_channel_l2cap = l2cap_packets.BasicFrameBuilder(1, close_channel)
        self.cert_send_b_frame(close_channel_l2cap)

        assertThat(self.cert_acl).emits(
            L2capMatchers.DisconnectionResponse(scid, dcid))

    def test_disconnect_on_timeout(self):
        """
        L2CAP/COS/CED/BV-08-C
        """
        self._setup_link_from_cert()

        scid = 0x41
        psm = 0x33

        # Don't send configuration request or response back
        self.cert_l2cap.ignore_config_and_connections()

        self._open_channel(1, scid, psm)

        assertThat(self.cert_acl).emitsNone(
            L2capMatchers.ConfigurationResponse())

    def test_retry_config_after_rejection(self):
        """
        L2CAP/COS/CFD/BV-02-C
        """
        self._setup_link_from_cert()

        psm = 0x33
        scid = 0x41

        self.cert_l2cap.reply_with_unacceptable_parameters()

        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC)

        assertThat(self.cert_acl).emits(L2capMatchers.ConfigurationResponse())
        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationRequest(), at_least_times=2)

    def test_config_unknown_options_with_hint(self):
        """
        L2CAP/COS/CFD/BV-12-C
        """
        self._setup_link_from_cert()
        self.cert_l2cap.reply_with_unknown_options_and_hint()

        self._open_channel(signal_id=1, scid=0x41, psm=0x33)

        assertThat(self.cert_acl).emits(L2capMatchers.ConfigurationResponse())

    def test_respond_to_echo_request(self):
        """
        L2CAP/COS/ECH/BV-01-C [Respond to Echo Request]
        Verify that the IUT responds to an echo request.
        """
        self._setup_link_from_cert()

        echo_request = l2cap_packets.EchoRequestBuilder(
            100, l2cap_packets.DisconnectionRequestBuilder(1, 2, 3))
        echo_request_l2cap = l2cap_packets.BasicFrameBuilder(1, echo_request)
        self.cert_send_b_frame(echo_request_l2cap)

        assertThat(self.cert_acl).emits(
            lambda packet: b"\x06\x01\x04\x00\x02\x00\x03\x00" in packet.payload
        )

    def test_reject_unknown_command(self):
        """
        L2CAP/COS/CED/BI-01-C
        """
        self._setup_link_from_cert()

        invalid_command_packet = b"\x04\x00\x01\x00\xff\x01\x00\x00"
        self.cert_acl.send(invalid_command_packet)

        assertThat(self.cert_acl).emits(L2capMatchers.CommandReject())

    def test_query_for_1_2_features(self):
        """
        L2CAP/COS/IEX/BV-01-C [Query for 1.2 Features]
        """
        self._setup_link_from_cert()
        signal_id = 3
        information_request = l2cap_packets.InformationRequestBuilder(
            signal_id,
            l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED
        )
        information_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, information_request)
        self.cert_send_b_frame(information_request_l2cap)

        def is_correct_information_response(l2cap_packet):
            packet_bytes = l2cap_packet.payload
            l2cap_view = l2cap_packets.BasicFrameView(
                bt_packets.PacketViewLittleEndian(list(packet_bytes)))
            if l2cap_view.GetChannelId() != 1:
                return False
            l2cap_control_view = l2cap_packets.ControlView(
                l2cap_view.GetPayload())
            if l2cap_control_view.GetCode(
            ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                return False
            information_response_view = l2cap_packets.InformationResponseView(
                l2cap_control_view)
            return information_response_view.GetInfoType(
            ) == l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED

        assertThat(self.cert_acl).emits(is_correct_information_response)

    def test_extended_feature_info_response_ertm(self):
        """
        L2CAP/EXF/BV-01-C [Extended Features Information Response for Enhanced
        Retransmission Mode]
        """
        self._setup_link_from_cert()

        signal_id = 3
        information_request = l2cap_packets.InformationRequestBuilder(
            signal_id,
            l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED
        )
        information_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, information_request)
        self.cert_send_b_frame(information_request_l2cap)

        def is_correct_information_response(l2cap_packet):
            packet_bytes = l2cap_packet.payload
            l2cap_view = l2cap_packets.BasicFrameView(
                bt_packets.PacketViewLittleEndian(list(packet_bytes)))
            if l2cap_view.GetChannelId() != 1:
                return False
            l2cap_control_view = l2cap_packets.ControlView(
                l2cap_view.GetPayload())
            if l2cap_control_view.GetCode(
            ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                return False
            information_response_view = l2cap_packets.InformationResponseView(
                l2cap_control_view)
            if information_response_view.GetInfoType(
            ) != l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
                return False
            extended_features_view = l2cap_packets.InformationResponseExtendedFeaturesView(
                information_response_view)
            return extended_features_view.GetEnhancedRetransmissionMode()

        assertThat(self.cert_acl).emits(is_correct_information_response)

    def test_extended_feature_info_response_streaming(self):
        """
        L2CAP/EXF/BV-02-C
        """
        asserts.skip("Streaming not supported")
        self._setup_link_from_cert()

        signal_id = 3
        information_request = l2cap_packets.InformationRequestBuilder(
            signal_id,
            l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED
        )
        information_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, information_request)
        self.cert_send_b_frame(information_request_l2cap)

        def is_correct_information_response(l2cap_packet):
            packet_bytes = l2cap_packet.payload
            l2cap_view = l2cap_packets.BasicFrameView(
                bt_packets.PacketViewLittleEndian(list(packet_bytes)))
            if l2cap_view.GetChannelId() != 1:
                return False
            l2cap_control_view = l2cap_packets.ControlView(
                l2cap_view.GetPayload())
            if l2cap_control_view.GetCode(
            ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                return False
            information_response_view = l2cap_packets.InformationResponseView(
                l2cap_control_view)
            if information_response_view.GetInfoType(
            ) != l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
                return False
            extended_features_view = l2cap_packets.InformationResponseExtendedFeaturesView(
                information_response_view)
            return extended_features_view.GetStreamingMode()

        assertThat(self.cert_acl).emits(is_correct_information_response)

    def test_extended_feature_info_response_fcs(self):
        """
        L2CAP/EXF/BV-03-C [Extended Features Information Response for FCS Option]
        Note: This is not mandated by L2CAP Spec
        """
        self._setup_link_from_cert()

        signal_id = 3
        information_request = l2cap_packets.InformationRequestBuilder(
            signal_id,
            l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED
        )
        information_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, information_request)
        self.cert_send_b_frame(information_request_l2cap)

        def is_correct_information_response(l2cap_packet):
            packet_bytes = l2cap_packet.payload
            l2cap_view = l2cap_packets.BasicFrameView(
                bt_packets.PacketViewLittleEndian(list(packet_bytes)))
            if l2cap_view.GetChannelId() != 1:
                return False
            l2cap_control_view = l2cap_packets.ControlView(
                l2cap_view.GetPayload())
            if l2cap_control_view.GetCode(
            ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                return False
            information_response_view = l2cap_packets.InformationResponseView(
                l2cap_control_view)
            if information_response_view.GetInfoType(
            ) != l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
                return False
            extended_features_view = l2cap_packets.InformationResponseExtendedFeaturesView(
                information_response_view)
            return extended_features_view.GetFcsOption()

        assertThat(self.cert_acl).emits(is_correct_information_response)

    def test_extended_feature_info_response_fixed_channels(self):
        """
        L2CAP/EXF/BV-05-C
        """
        self._setup_link_from_cert()

        signal_id = 3
        information_request = l2cap_packets.InformationRequestBuilder(
            signal_id,
            l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED
        )
        information_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, information_request)
        self.cert_send_b_frame(information_request_l2cap)

        def is_correct_information_response(l2cap_packet):
            packet_bytes = l2cap_packet.payload
            l2cap_view = l2cap_packets.BasicFrameView(
                bt_packets.PacketViewLittleEndian(list(packet_bytes)))
            if l2cap_view.GetChannelId() != 1:
                return False
            l2cap_control_view = l2cap_packets.ControlView(
                l2cap_view.GetPayload())
            if l2cap_control_view.GetCode(
            ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                return False
            information_response_view = l2cap_packets.InformationResponseView(
                l2cap_control_view)
            if information_response_view.GetInfoType(
            ) != l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
                return False
            extended_features_view = l2cap_packets.InformationResponseExtendedFeaturesView(
                information_response_view)
            return extended_features_view.GetFixedChannels()

        assertThat(self.cert_acl).emits(is_correct_information_response)

    def test_config_channel_not_use_FCS(self):
        """
        L2CAP/FOC/BV-01-C [IUT Initiated Configuration of the FCS Option]
        Verify the IUT can configure a channel to not use FCS in I/S-frames.
        """
        self._setup_link_from_cert()

        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(self.cert_acl).emits(lambda packet: b"abc" in packet.payload)

    def test_explicitly_request_use_FCS(self):
        """
        L2CAP/FOC/BV-02-C [Lower Tester Explicitly Requests FCS should be Used]
        Verify the IUT will include the FCS in I/S-frames if the Lower Tester explicitly requests that FCS
        should be used.
        """
        self._setup_link_from_cert()

        self.cert_l2cap.turn_on_ertm_and_fcs()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(
            self.cert_acl).emits(lambda packet: b"abc\x4f\xa3" in packet.payload
                                )  # TODO: Use packet parser

    def test_implicitly_request_use_FCS(self):
        """
        L2CAP/FOC/BV-03-C [Lower Tester Implicitly Requests FCS should be Used]
        TODO: Update this test case. What's the difference between this one and test_explicitly_request_use_FCS?
        """
        self._setup_link_from_cert()

        self.cert_l2cap.turn_on_ertm_and_fcs()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(
            self.cert_acl).emits(lambda packet: b"abc\x4f\xa3" in packet.payload
                                )  # TODO: Use packet parser

    def test_transmit_i_frames(self):
        """
        L2CAP/ERM/BV-01-C [Transmit I-frames]
        """
        self._setup_link_from_cert()

        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        dcid = self.cert_l2cap.get_dcid(scid)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(self.cert_acl).emits(lambda packet: b"abc" in packet.payload)

        # Assemble a sample packet. TODO: Use RawBuilder
        SAMPLE_PACKET = l2cap_packets.CommandRejectNotUnderstoodBuilder(1)

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 0, l2cap_packets.Final.NOT_SET, 1,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(self.cert_acl).emits(lambda packet: b"abc" in packet.payload)

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 1, l2cap_packets.Final.NOT_SET, 2,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(self.cert_acl).emits(lambda packet: b"abc" in packet.payload)

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 2, l2cap_packets.Final.NOT_SET, 3,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

    def test_receive_i_frames(self):
        """
        L2CAP/ERM/BV-02-C [Receive I-Frames]
        Verify the IUT can receive in-sequence valid I-frames and deliver L2CAP SDUs to the Upper Tester
        """
        self._setup_link_from_cert()

        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        dcid = self.cert_l2cap.get_dcid(scid)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        for i in range(3):
            i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
                dcid, i, l2cap_packets.Final.NOT_SET, 0,
                l2cap_packets.SegmentationAndReassembly.UNSEGMENTED,
                SAMPLE_PACKET)
            self.cert_send_b_frame(i_frame)
            assertThat(self.cert_acl).emits(
                L2capMatchers.SupervisoryFrame(scid, req_seq=i + 1))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 3, l2cap_packets.Final.NOT_SET, 0,
            l2cap_packets.SegmentationAndReassembly.START, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, req_seq=4))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 4, l2cap_packets.Final.NOT_SET, 0,
            l2cap_packets.SegmentationAndReassembly.CONTINUATION, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, req_seq=5))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 5, l2cap_packets.Final.NOT_SET, 0,
            l2cap_packets.SegmentationAndReassembly.END, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, req_seq=6))

    def test_acknowledging_received_i_frames(self):
        """
        L2CAP/ERM/BV-03-C [Acknowledging Received I-Frames]
        Verify the IUT sends S-frame [RR] with the Poll bit not set to acknowledge data received from the
        Lower Tester
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        dcid = self.cert_l2cap.get_dcid(scid)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        for i in range(3):
            i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
                dcid, i, l2cap_packets.Final.NOT_SET, 0,
                l2cap_packets.SegmentationAndReassembly.UNSEGMENTED,
                SAMPLE_PACKET)
            self.cert_send_b_frame(i_frame)
            assertThat(self.cert_acl).emits(
                L2capMatchers.SupervisoryFrame(scid, req_seq=i + 1))

        assertThat(self.cert_acl).emitsNone(
            L2capMatchers.SupervisoryFrame(scid, req_seq=4),
            timeout=timedelta(seconds=1))

    def test_resume_transmitting_when_received_rr(self):
        """
        L2CAP/ERM/BV-05-C [Resume Transmitting I-Frames when an S-Frame [RR] is Received]
        Verify the IUT will cease transmission of I-frames when the negotiated TxWindow is full. Verify the
        IUT will resume transmission of I-frames when an S-frame [RR] is received that acknowledges
        previously sent I-frames.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=1)

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        dcid = self.cert_l2cap.get_dcid(scid)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'def'))

        # TODO: Besides checking TxSeq, we also want to check payload, once we can get it from packet view
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))
        assertThat(self.cert_acl).emitsNone(
            L2capMatchers.InformationFrame(scid, tx_seq=1))
        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.RECEIVER_READY,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.POLL_RESPONSE, 1)
        self.cert_send_b_frame(s_frame)
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=1))

    def test_resume_transmitting_when_acknowledge_previously_sent(self):
        """
        L2CAP/ERM/BV-06-C [Resume Transmitting I-Frames when an I-Frame is Received]
        Verify the IUT will cease transmission of I-frames when the negotiated TxWindow is full. Verify the
        IUT will resume transmission of I-frames when an I-frame is received that acknowledges previously
        sent I-frames.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=1)

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        dcid = self.cert_l2cap.get_dcid(scid)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'def'))

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))
        # TODO: If 1 second is greater than their retransmit timeout, use a smaller timeout
        assertThat(self.cert_acl).emitsNone(
            L2capMatchers.InformationFrame(scid, tx_seq=1),
            timeout=timedelta(seconds=1))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 0, l2cap_packets.Final.NOT_SET, 1,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=1))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 1, l2cap_packets.Final.NOT_SET, 2,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

    def test_transmit_s_frame_rr_with_poll_bit_set(self):
        """
        L2CAP/ERM/BV-08-C [Send S-Frame [RR] with Poll Bit Set]
        Verify the IUT sends an S-frame [RR] with the Poll bit set when its retransmission timer expires.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, p=l2cap_packets.Poll.POLL))

    def test_transmit_s_frame_rr_with_final_bit_set(self):
        """
        L2CAP/ERM/BV-09-C [Send S-Frame [RR] with Final Bit Set]
        Verify the IUT responds with an S-frame [RR] with the Final bit set after receiving an S-frame [RR]
        with the Poll bit set.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.RECEIVER_READY,
            l2cap_packets.Poll.POLL, l2cap_packets.Final.NOT_SET, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(
                scid, f=l2cap_packets.Final.POLL_RESPONSE))

    def test_s_frame_transmissions_exceed_max_transmit(self):
        """
        L2CAP/ERM/BV-11-C [S-Frame Transmissions Exceed MaxTransmit]
        Verify the IUT will close the channel when the Monitor Timer expires.
        """
        asserts.skip("Need to configure DUT to have a shorter timer")
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))

        # Retransmission timer = 2, 20 * monitor timer = 360, so total timeout is 362
        time.sleep(362)
        assertThat(self.cert_acl).emits(L2capMatchers.DisconnectionRequest())

    def test_i_frame_transmissions_exceed_max_transmit(self):
        """
        L2CAP/ERM/BV-12-C [I-Frame Transmissions Exceed MaxTransmit]
        Verify the IUT will close the channel when it receives an S-frame [RR] with the final bit set that does
        not acknowledge the previous I-frame sent by the IUT.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))

        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.RECEIVER_READY,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.POLL_RESPONSE, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emits(L2capMatchers.DisconnectionRequest())

    def test_respond_to_rej(self):
        """
        L2CAP/ERM/BV-13-C [Respond to S-Frame [REJ]]
        Verify the IUT retransmits I-frames starting from the sequence number specified in the S-frame [REJ].
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=2, max_transmit=2)

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        for i in range(2):
            assertThat(self.cert_acl).emits(
                L2capMatchers.InformationFrame(scid, tx_seq=i),
                timeout=timedelta(seconds=0.5))

        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.REJECT,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.NOT_SET, 0)
        self.cert_send_b_frame(s_frame)

        for i in range(2):
            assertThat(self.cert_acl).emits(
                L2capMatchers.InformationFrame(scid, tx_seq=i),
                timeout=timedelta(seconds=0.5))

    def test_receive_s_frame_rr_final_bit_set(self):
        """
        L2CAP/ERM/BV-18-C [Receive S-Frame [RR] Final Bit = 1]
        Verify the IUT will retransmit any previously sent I-frames unacknowledged by receipt of an S-Frame
        [RR] with the Final Bit set.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))

        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, p=l2cap_packets.Poll.POLL))

        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.RECEIVER_READY,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.POLL_RESPONSE, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))

    def test_receive_i_frame_final_bit_set(self):
        """
        L2CAP/ERM/BV-19-C [Receive I-Frame Final Bit = 1]
        Verify the IUT will retransmit any previously sent I-frames unacknowledged by receipt of an I-frame
        with the final bit set.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))

        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, p=l2cap_packets.Poll.POLL))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 0, l2cap_packets.Final.POLL_RESPONSE, 0,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))

    def test_recieve_rnr(self):
        """
        L2CAP/ERM/BV-20-C [Enter Remote Busy Condition]
        Verify the IUT will not retransmit any I-frames when it receives a remote busy indication from the
        Lower Tester (S-frame [RNR]).
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=b'abc'))

        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, p=l2cap_packets.Poll.POLL))

        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.RECEIVER_NOT_READY,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.POLL_RESPONSE, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emitsNone(
            L2capMatchers.InformationFrame(scid, tx_seq=0))

    def test_sent_rej_lost(self):
        """
        L2CAP/ERM/BI-01-C [S-Frame [REJ] Lost or Corrupted]
        Verify the IUT can handle receipt of an S-=frame [RR] Poll = 1 if the S-frame [REJ] sent from the IUT
        is lost.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=5)
        ertm_tx_window_size = 5

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 0, l2cap_packets.Final.NOT_SET, 0,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, req_seq=1))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, ertm_tx_window_size - 1, l2cap_packets.Final.NOT_SET, 0,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(
                scid, s=l2cap_packets.SupervisoryFunction.REJECT))

        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.RECEIVER_READY,
            l2cap_packets.Poll.POLL, l2cap_packets.Final.NOT_SET, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(
                scid, req_seq=1, f=l2cap_packets.Final.POLL_RESPONSE))
        for i in range(1, ertm_tx_window_size):
            i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
                dcid, i, l2cap_packets.Final.NOT_SET, 0,
                l2cap_packets.SegmentationAndReassembly.UNSEGMENTED,
                SAMPLE_PACKET)
            self.cert_send_b_frame(i_frame)
            assertThat(self.cert_acl).emits(
                L2capMatchers.SupervisoryFrame(scid, req_seq=i + 1))

    def test_handle_duplicate_srej(self):
        """
        L2CAP/ERM/BI-03-C [Handle Duplicate S-Frame [SREJ]]
        Verify the IUT will only retransmit the requested I-frame once after receiving a duplicate SREJ.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0),
            timeout=timedelta(0.5))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=1),
            timeout=timedelta(0.5))
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, p=l2cap_packets.Poll.POLL))

        # Send SREJ with F not set
        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.SELECT_REJECT,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.NOT_SET, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emitsNone(timeout=timedelta(seconds=0.5))
        # Send SREJ with F set
        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.SELECT_REJECT,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.POLL_RESPONSE, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))

    def test_handle_receipt_rej_and_rr_with_f_set(self):
        """
        L2CAP/ERM/BI-04-C [Handle Receipt of S-Frame [REJ] and S-Frame [RR, F=1] that Both Require Retransmission of the Same I-Frames]
        Verify the IUT will only retransmit the requested I-frames once after receiving an S-frame [REJ]
        followed by an S-frame [RR] with the Final bit set that indicates the same I-frames should be
        retransmitted.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0),
            timeout=timedelta(0.5))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=1),
            timeout=timedelta(0.5))
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, p=l2cap_packets.Poll.POLL),
            timeout=timedelta(2))

        # Send REJ with F not set
        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.REJECT,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.NOT_SET, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emitsNone(timeout=timedelta(seconds=0.5))

        # Send RR with F set
        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.REJECT,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.POLL_RESPONSE, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=1))

    def test_handle_rej_and_i_frame_with_f_set(self):
        """
        L2CAP/ERM/BI-05-C [Handle receipt of S-Frame [REJ] and I-Frame [F=1] that Both Require Retransmission of the Same I-Frames]
        Verify the IUT will only retransmit the requested I-frames once after receiving an S-frame [REJ]
        followed by an I-frame with the Final bit set that indicates the same I-frames should be retransmitted.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        assertThat(self.cert_acl).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        dcid = self.cert_l2cap.get_dcid(scid)

        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        self.dut.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0),
            timeout=timedelta(0.5))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=1),
            timeout=timedelta(0.5))
        assertThat(self.cert_acl).emits(
            L2capMatchers.SupervisoryFrame(scid, p=l2cap_packets.Poll.POLL),
            timeout=timedelta(2))

        # Send SREJ with F not set
        s_frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            dcid, l2cap_packets.SupervisoryFunction.SELECT_REJECT,
            l2cap_packets.Poll.NOT_SET, l2cap_packets.Final.NOT_SET, 0)
        self.cert_send_b_frame(s_frame)

        assertThat(self.cert_acl).emitsNone(timeout=timedelta(seconds=0.5))

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            dcid, 0, l2cap_packets.Final.POLL_RESPONSE, 0,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_send_b_frame(i_frame)

        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=0))
        assertThat(self.cert_acl).emits(
            L2capMatchers.InformationFrame(scid, tx_seq=1))

    def test_initiated_configuration_request_ertm(self):
        """
        L2CAP/CMC/BV-01-C [IUT Initiated Configuration of Enhanced Retransmission Mode]
        Verify the IUT can send a Configuration Request command containing the F&EC option that specifies
        Enhanced Retransmission Mode.
        """
        self._setup_link_from_cert()

        self.cert_l2cap.turn_on_ertm()

        psm = 0x33
        scid = 0x41
        self._open_channel(
            1,
            scid,
            psm,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

        # TODO: Fix this test. It doesn't work so far with PDL struct

        assertThat(self.cert_acl).emits(L2capMatchers.ConfigurationRequest())
        asserts.skip("Struct not working")

    def test_respond_configuration_request_ertm(self):
        """
        L2CAP/CMC/BV-02-C [Lower Tester Initiated Configuration of Enhanced Retransmission Mode]
        Verify the IUT can accept a Configuration Request from the Lower Tester containing an F&EC option
        that specifies Enhanced Retransmission Mode.
        """
        self._setup_link_from_cert()

        psm = 1
        scid = 0x0101
        self.retransmission_mode = l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM
        self.dut.l2cap.SetDynamicChannel(
            l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                psm=psm, retransmission_mode=self.retransmission_mode))

        open_channel = l2cap_packets.ConnectionRequestBuilder(1, psm, scid)
        open_channel_l2cap = l2cap_packets.BasicFrameBuilder(1, open_channel)
        self.cert_send_b_frame(open_channel_l2cap)

        # TODO: Verify that the type should be ERTM
        assertThat(self.cert_acl).emits(L2capMatchers.ConfigurationResponse())
