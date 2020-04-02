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

from cert.gd_base_test import GdBaseTestClass
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
from bluetooth_packets_python3.l2cap_packets import SegmentationAndReassembly
from bluetooth_packets_python3.l2cap_packets import Final
from bluetooth_packets_python3.l2cap_packets import CommandCode
from bluetooth_packets_python3.l2cap_packets import SupervisoryFunction
from bluetooth_packets_python3.l2cap_packets import Poll
from bluetooth_packets_python3.l2cap_packets import InformationRequestInfoType
from l2cap.classic.cert.cert_l2cap import CertL2cap
from l2cap.classic.facade_pb2 import RetransmissionFlowControlMode

# Assemble a sample packet. TODO: Use RawBuilder
SAMPLE_PACKET = l2cap_packets.CommandRejectNotUnderstoodBuilder(1)


class L2capTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='L2CAP', cert_module='HCI_INTERFACES')

    def setup_test(self):
        super().setup_test()

        self.dut.address = self.dut.hci_controller.GetMacAddressSimple()
        self.cert.address = self.cert.controller_read_only_property.ReadLocalAddress(
            empty_proto.Empty()).address
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert.address)

        self.dut_l2cap = PyL2cap(self.dut, self.cert_address)
        self.cert_l2cap = CertL2cap(self.cert)

    def teardown_test(self):
        self.cert_l2cap.close()
        self.dut_l2cap.close()
        super().teardown_test()

    def cert_send_b_frame(self, b_frame):
        self.cert_l2cap.send_acl(b_frame)

    def _setup_link_from_cert(self):
        self.dut.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))
        self.cert_l2cap.connect_acl(self.dut.address)

    def _open_unvalidated_channel(self,
                                  signal_id=1,
                                  scid=0x0101,
                                  psm=0x33,
                                  mode=RetransmissionFlowControlMode.BASIC):

        dut_channel = self.dut_l2cap.register_dynamic_channel(psm, mode)
        cert_channel = self.cert_l2cap.open_channel(signal_id, psm, scid)

        return (dut_channel, cert_channel)

    def _open_channel(self,
                      signal_id=1,
                      scid=0x0101,
                      psm=0x33,
                      mode=RetransmissionFlowControlMode.BASIC):
        result = self._open_unvalidated_channel(signal_id, scid, psm, mode)

        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

        return result

    def _open_channel_from_dut(self,
                               psm=0x33,
                               mode=RetransmissionFlowControlMode.BASIC):
        dut_channel_future = self.dut_l2cap.connect_dynamic_channel_to_cert(
            psm, mode)
        cert_channel = self.cert_l2cap.verify_and_respond_open_channel_from_remote(
            psm)
        dut_channel = dut_channel_future.get_channel()

        return (dut_channel, cert_channel)

    def test_connect_dynamic_channel_and_send_data(self):
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel(scid=0x41, psm=0x33)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(L2capMatchers.Data(b'abc'))

    def test_receive_packet_from_unknown_channel(self):
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel(scid=0x41, psm=0x33)

        i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
            0x99, 0, Final.NOT_SET, 1,
            l2cap_packets.SegmentationAndReassembly.UNSEGMENTED, SAMPLE_PACKET)
        self.cert_l2cap.send_acl(i_frame)
        assertThat(cert_channel).emitsNone(
            L2capMatchers.SFrame(req_seq=4), timeout=timedelta(seconds=1))

    def test_open_two_channels(self):
        self._setup_link_from_cert()

        self._open_channel(signal_id=1, scid=0x41, psm=0x41)
        self._open_channel(signal_id=2, scid=0x43, psm=0x43)

    def test_connect_and_send_data_ertm_no_segmentation(self):
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc' * 34)
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc' * 34))

        cert_channel.send_i_frame(tx_seq=0, req_seq=1, payload=SAMPLE_PACKET)
        # todo verify received?

    def test_basic_operation_request_connection(self):
        """
        L2CAP/COS/CED/BV-01-C [Request Connection]
        Verify that the IUT is able to request the connection establishment for an L2CAP data channel and
        initiate the configuration procedure.
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_dut(psm=0x33)

    def test_send_data(self):
        """
        L2CAP/COS/CED/BV-03-C [Send data]
        """
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel(scid=0x41, psm=0x33)
        dut_channel.send(b'hello')
        assertThat(cert_channel).emits(L2capMatchers.Data(b'hello'))

    def test_disconnect(self):
        """
        L2CAP/COS/CED/BV-04-C [Disconnect]
        """
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel(scid=0x41, psm=0x33)
        dut_channel.close_channel()
        cert_channel.verify_disconnect_request()

    def test_accept_connection(self):
        """
        L2CAP/COS/CED/BV-05-C [Accept connection]
        Also verify that DUT can send 48 bytes PDU (minimal MTU)
        """
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel(scid=0x41, psm=0x33)
        dut_channel.send(b'a' * 48)
        assertThat(cert_channel).emits(L2capMatchers.Data(b'a' * 48))

    def test_accept_disconnect(self):
        """
        L2CAP/COS/CED/BV-07-C
        """
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel(scid=0x41, psm=0x33)
        cert_channel.disconnect_and_verify()

    def test_disconnect_on_timeout(self):
        """
        L2CAP/COS/CED/BV-08-C
        """
        self._setup_link_from_cert()
        self.cert_l2cap.ignore_config_and_connections()

        self._open_unvalidated_channel(scid=0x41, psm=0x33)

        assertThat(self.cert_l2cap.get_control_channel()).emitsNone(
            L2capMatchers.ConfigurationResponse())

    def test_continuation_flag(self):
        """
        L2CAP/COS/CFD/BV-01-C [Continuation Flag]
        Verify the IUT is able to receive configuration requests that have the continuation flag set.
        """
        cert_acl_handle = self._setup_link_from_cert()

        # Send configuration request with CONTINUE
        self.cert_l2cap.reply_with_continuation_flag()

        (dut_channel, cert_channel) = self._open_unvalidated_channel(
            scid=0x41, psm=0x33)

        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationResponse(), at_least_times=2)

    def test_retry_config_after_rejection(self):
        """
        L2CAP/COS/CFD/BV-02-C
        """
        self._setup_link_from_cert()

        self.cert_l2cap.reply_with_unacceptable_parameters()

        self._open_unvalidated_channel(scid=0x41, psm=0x33)

        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

    def test_send_requested_options(self):
        """
        L2CAP/COS/CFD/BV-03-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel(scid=0x41, psm=0x33)

    def test_non_blocking_config_response(self):
        """
        L2CAP/COS/CFD/BV-08-C
        """
        self._setup_link_from_cert()

        self.cert_l2cap.ignore_config_request()

        self._open_unvalidated_channel(scid=0x41, psm=0x33)

        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationResponse(),
            L2capMatchers.ConfigurationRequest()).inAnyOrder()

    def test_config_unknown_options_with_hint(self):
        """
        L2CAP/COS/CFD/BV-12-C
        """
        self._setup_link_from_cert()
        self.cert_l2cap.reply_with_unknown_options_and_hint()

        self._open_unvalidated_channel(scid=0x41, psm=0x33)

        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationResponse())

    def test_respond_to_echo_request(self):
        """
        L2CAP/COS/ECH/BV-01-C [Respond to Echo Request]
        Verify that the IUT responds to an echo request.
        """
        self._setup_link_from_cert()

        echo_request = l2cap_packets.EchoRequestBuilder(
            100, l2cap_packets.DisconnectionRequestBuilder(1, 2, 3))
        self.cert_l2cap.get_control_channel().send(echo_request)

        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.PartialData(b"\x06\x01\x04\x00\x02\x00\x03\x00"))

    def test_reject_unknown_command(self):
        """
        L2CAP/COS/CED/BI-01-C
        """
        self._setup_link_from_cert()

        asserts.skip("Need to use packet builders (RawBuilder)")

        # TODO(hsz): Use packet builders with opcode 0xff, sid 0x1, size 0x0
        invalid_command_packet = b"\xff\x01\x00\x00"
        self.cert_l2cap.get_control_channel().send(invalid_command_packet)

        assertThat(self.cert_channel).emits(L2capMatchers.CommandReject())

    def test_respond_with_1_2_features(self):
        """
        L2CAP/COS/IEX/BV-02-C [Respond with 1.2 Features]
        """
        self._setup_link_from_cert()
        control_channel = self.cert_l2cap.get_control_channel()

        control_channel.send_extended_features_request()

        assertThat(control_channel).emits(
            L2capMatchers.InformationResponseExtendedFeatures())

    def test_extended_feature_info_response_ertm(self):
        """
        L2CAP/EXF/BV-01-C [Extended Features Information Response for Enhanced
        Retransmission Mode]
        """
        self._setup_link_from_cert()
        control_channel = self.cert_l2cap.get_control_channel()

        control_channel.send_extended_features_request()

        assertThat(control_channel).emits(
            L2capMatchers.InformationResponseExtendedFeatures(
                supports_ertm=True))

    def test_extended_feature_info_response_streaming(self):
        """
        L2CAP/EXF/BV-02-C
        """
        asserts.skip("Streaming not supported")
        self._setup_link_from_cert()
        control_channel = self.cert_l2cap.get_control_channel()

        control_channel.send_extended_features_request()

        assertThat(control_channel).emits(
            L2capMatchers.InformationResponseExtendedFeatures(
                supports_streaming=True))

    def test_extended_feature_info_response_fcs(self):
        """
        L2CAP/EXF/BV-03-C [Extended Features Information Response for FCS Option]
        Note: This is not mandated by L2CAP Spec
        """
        self._setup_link_from_cert()
        control_channel = self.cert_l2cap.get_control_channel()

        control_channel.send_extended_features_request()

        assertThat(control_channel).emits(
            L2capMatchers.InformationResponseExtendedFeatures(
                supports_fcs=True))

    def test_extended_feature_info_response_fixed_channels(self):
        """
        L2CAP/EXF/BV-05-C
        """
        self._setup_link_from_cert()
        control_channel = self.cert_l2cap.get_control_channel()

        control_channel.send_extended_features_request()

        assertThat(control_channel).emits(
            L2capMatchers.InformationResponseExtendedFeatures(
                supports_fixed_channels=True))

    def test_config_channel_not_use_FCS(self):
        """
        L2CAP/FOC/BV-01-C [IUT Initiated Configuration of the FCS Option]
        Verify the IUT can configure a channel to not use FCS in I/S-frames.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'))

    def test_explicitly_request_use_FCS(self):
        """
        L2CAP/FOC/BV-02-C [Lower Tester Explicitly Requests FCS should be Used]
        Verify the IUT will include the FCS in I/S-frames if the Lower Tester explicitly requests that FCS
        should be used.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()
        self.cert_l2cap.turn_on_fcs()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.PartialData(
                b"abc\x4f\xa3"))  # TODO: Use packet parser

    def test_implicitly_request_use_FCS(self):
        """
        L2CAP/FOC/BV-03-C [Lower Tester Implicitly Requests FCS should be Used]
        TODO: Update this test case. What's the difference between this one and test_explicitly_request_use_FCS?
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()
        self.cert_l2cap.turn_on_fcs()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.PartialData(
                b"abc\x4f\xa3"))  # TODO: Use packet parser

    def test_transmit_i_frames(self):
        """
        L2CAP/ERM/BV-01-C [Transmit I-frames]
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b"abc"))

        # Assemble a sample packet. TODO: Use RawBuilder
        SAMPLE_PACKET = l2cap_packets.CommandRejectNotUnderstoodBuilder(1)

        # todo: verify packet received?
        cert_channel.send_i_frame(tx_seq=0, req_seq=1, payload=SAMPLE_PACKET)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=1, payload=b"abc"))

        cert_channel.send_i_frame(tx_seq=1, req_seq=2, payload=SAMPLE_PACKET)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(L2capMatchers.PartialData(b"abc"))

        cert_channel.send_i_frame(tx_seq=2, req_seq=3, payload=SAMPLE_PACKET)

    def test_receive_i_frames(self):
        """
        L2CAP/ERM/BV-02-C [Receive I-Frames]
        Verify the IUT can receive in-sequence valid I-frames and deliver L2CAP SDUs to the Upper Tester
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        for i in range(3):
            cert_channel.send_i_frame(
                tx_seq=i, req_seq=0, payload=SAMPLE_PACKET)
            assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=i + 1))

        cert_channel.send_i_frame(
            tx_seq=3,
            req_seq=0,
            sar=SegmentationAndReassembly.START,
            payload=SAMPLE_PACKET)
        assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=4))

        cert_channel.send_i_frame(
            tx_seq=4,
            req_seq=0,
            sar=SegmentationAndReassembly.CONTINUATION,
            payload=SAMPLE_PACKET)
        assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=5))

        cert_channel.send_i_frame(
            tx_seq=5,
            req_seq=0,
            sar=SegmentationAndReassembly.END,
            payload=SAMPLE_PACKET)
        assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=6))

    def test_acknowledging_received_i_frames(self):
        """
        L2CAP/ERM/BV-03-C [Acknowledging Received I-Frames]
        Verify the IUT sends S-frame [RR] with the Poll bit not set to acknowledge data received from the
        Lower Tester
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        for i in range(3):
            cert_channel.send_i_frame(
                tx_seq=i, req_seq=0, payload=SAMPLE_PACKET)
            assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=i + 1))

        assertThat(cert_channel).emitsNone(
            L2capMatchers.SFrame(req_seq=4), timeout=timedelta(seconds=1))

    def test_resume_transmitting_when_received_rr(self):
        """
        L2CAP/ERM/BV-05-C [Resume Transmitting I-Frames when an S-Frame [RR] is Received]
        Verify the IUT will cease transmission of I-frames when the negotiated TxWindow is full. Verify the
        IUT will resume transmission of I-frames when an S-frame [RR] is received that acknowledges
        previously sent I-frames.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=1)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        dut_channel.send(b'def')

        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'))
        assertThat(cert_channel).emitsNone(
            L2capMatchers.IFrame(tx_seq=1, payload=b'def'))

        cert_channel.send_s_frame(req_seq=1, f=Final.POLL_RESPONSE)
        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=1))

    def test_resume_transmitting_when_acknowledge_previously_sent(self):
        """
        L2CAP/ERM/BV-06-C [Resume Transmitting I-Frames when an I-Frame is Received]
        Verify the IUT will cease transmission of I-frames when the negotiated TxWindow is full. Verify the
        IUT will resume transmission of I-frames when an I-frame is received that acknowledges previously
        sent I-frames.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=1)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        dut_channel.send(b'def')

        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'))
        # TODO: If 1 second is greater than their retransmit timeout, use a smaller timeout
        assertThat(cert_channel).emitsNone(
            L2capMatchers.IFrame(tx_seq=1, payload=b'abc'),
            timeout=timedelta(seconds=1))

        cert_channel.send_i_frame(tx_seq=0, req_seq=1, payload=SAMPLE_PACKET)

        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=1, payload=b'def'))

        cert_channel.send_i_frame(tx_seq=1, req_seq=2, payload=SAMPLE_PACKET)

    def test_transmit_s_frame_rr_with_poll_bit_set(self):
        """
        L2CAP/ERM/BV-08-C [Send S-Frame [RR] with Poll Bit Set]
        Verify the IUT sends an S-frame [RR] with the Poll bit set when its retransmission timer expires.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(cert_channel).emits(
            L2capMatchers.SFrame(p=l2cap_packets.Poll.POLL))

    def test_transmit_s_frame_rr_with_final_bit_set(self):
        """
        L2CAP/ERM/BV-09-C [Send S-Frame [RR] with Final Bit Set]
        Verify the IUT responds with an S-frame [RR] with the Final bit set after receiving an S-frame [RR]
        with the Poll bit set.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        cert_channel.send_s_frame(req_seq=0, p=Poll.POLL)
        assertThat(cert_channel).emits(
            L2capMatchers.SFrame(f=Final.POLL_RESPONSE))

    def test_retransmit_s_frame_rr_with_poll_bit_set(self):
        """
        L2CAP/ERM/BV-10-C [Send S-Frame [RR] with Final Bit Set]
        Verify the IUT responds with an S-frame [RR] with the Final bit set after receiving an S-frame [RR]
        with the Poll bit set.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(max_transmit=3)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)
        dut_channel.send(b'abc')

        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'))
        assertThat(cert_channel).emits(
            L2capMatchers.SFrame(req_seq=0, p=Poll.POLL, f=Final.NOT_SET))
        cert_channel.send_s_frame(req_seq=1, f=Final.POLL_RESPONSE)

    def test_s_frame_transmissions_exceed_max_transmit(self):
        """
        L2CAP/ERM/BV-11-C [S-Frame Transmissions Exceed MaxTransmit]
        Verify the IUT will close the channel when the Monitor Timer expires.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.reply_with_max_transmit_one()
        self.cert_l2cap.turn_on_ertm(tx_window_size=1, max_transmit=1)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')

        cert_channel.verify_disconnect_request()

    def test_i_frame_transmissions_exceed_max_transmit(self):
        """
        L2CAP/ERM/BV-12-C [I-Frame Transmissions Exceed MaxTransmit]
        """
        self._setup_link_from_cert()
        self.cert_l2cap.reply_with_max_transmit_one()
        self.cert_l2cap.turn_on_ertm(tx_window_size=1, max_transmit=1)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0),
            L2capMatchers.SFrame(p=Poll.POLL)).inOrder()

        cert_channel.send_s_frame(req_seq=0, f=Final.POLL_RESPONSE)
        cert_channel.verify_disconnect_request()

    def test_respond_to_rej(self):
        """
        L2CAP/ERM/BV-13-C [Respond to S-Frame [REJ]]
        Verify the IUT retransmits I-frames starting from the sequence number specified in the S-frame [REJ].
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=2, max_transmit=2)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'),
            L2capMatchers.IFrame(tx_seq=1, payload=b'abc')).inOrder()

        cert_channel.send_s_frame(req_seq=0, s=SupervisoryFunction.REJECT)

        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'),
            L2capMatchers.IFrame(tx_seq=1, payload=b'abc')).inOrder()

    def test_respond_to_srej_p_set(self):
        """
        L2CAP/ERM/BV-14-C [Respond to S-Frame [SREJ] POLL Bit Set]
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=3, max_transmit=2)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        for _ in range(4):
            dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'),
            L2capMatchers.IFrame(tx_seq=1, payload=b'abc'),
            L2capMatchers.IFrame(tx_seq=2, payload=b'abc')).inOrder()

        cert_channel.send_s_frame(
            req_seq=1, p=Poll.POLL, s=SupervisoryFunction.SELECT_REJECT)

        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(
                tx_seq=1, payload=b'abc', f=Final.POLL_RESPONSE),
            L2capMatchers.IFrame(tx_seq=3, payload=b'abc')).inOrder()

    def test_respond_to_srej_p_clear(self):
        """
        L2CAP/ERM/BV-15-C [Respond to S-Frame [SREJ] POLL Bit Clear]
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=3, max_transmit=2)

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        for _ in range(4):
            dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0, payload=b'abc'),
            L2capMatchers.IFrame(tx_seq=1, payload=b'abc'),
            L2capMatchers.IFrame(tx_seq=2, payload=b'abc')).inOrder()

        cert_channel.send_s_frame(
            req_seq=1, s=SupervisoryFunction.SELECT_REJECT)
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=1, payload=b'abc', f=Final.NOT_SET))
        cert_channel.send_s_frame(
            req_seq=3, s=SupervisoryFunction.RECEIVER_READY)
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=3, payload=b'abc', f=Final.NOT_SET))

    def test_receive_s_frame_rr_final_bit_set(self):
        """
        L2CAP/ERM/BV-18-C [Receive S-Frame [RR] Final Bit = 1]
        Verify the IUT will retransmit any previously sent I-frames unacknowledged by receipt of an S-Frame
        [RR] with the Final Bit set.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')

        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(cert_channel).emits(
            L2capMatchers.SFrame(p=l2cap_packets.Poll.POLL))

        cert_channel.send_s_frame(req_seq=0, f=Final.POLL_RESPONSE)
        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=0))

    def test_receive_i_frame_final_bit_set(self):
        """
        L2CAP/ERM/BV-19-C [Receive I-Frame Final Bit = 1]
        Verify the IUT will retransmit any previously sent I-frames unacknowledged by receipt of an I-frame
        with the final bit set.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')

        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(cert_channel).emits(L2capMatchers.SFrame(p=Poll.POLL))

        cert_channel.send_i_frame(
            tx_seq=0, req_seq=0, f=Final.POLL_RESPONSE, payload=SAMPLE_PACKET)

        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=0))

    def test_recieve_rnr(self):
        """
        L2CAP/ERM/BV-20-C [Enter Remote Busy Condition]
        Verify the IUT will not retransmit any I-frames when it receives a remote busy indication from the
        Lower Tester (S-frame [RNR]).
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')

        # TODO: Always use their retransmission timeout value
        time.sleep(2)
        assertThat(cert_channel).emits(
            L2capMatchers.SFrame(p=l2cap_packets.Poll.POLL))

        cert_channel.send_s_frame(
            req_seq=0,
            s=SupervisoryFunction.RECEIVER_NOT_READY,
            f=Final.POLL_RESPONSE)
        assertThat(cert_channel).emitsNone(L2capMatchers.IFrame(tx_seq=0))

    def test_sent_rej_lost(self):
        """
        L2CAP/ERM/BI-01-C [S-Frame [REJ] Lost or Corrupted]
        Verify the IUT can handle receipt of an S-=frame [RR] Poll = 1 if the S-frame [REJ] sent from the IUT
        is lost.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm(tx_window_size=5)
        ertm_tx_window_size = 5

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x41, mode=RetransmissionFlowControlMode.ERTM)

        cert_channel.send_i_frame(tx_seq=0, req_seq=0, payload=SAMPLE_PACKET)
        assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=1))

        cert_channel.send_i_frame(
            tx_seq=ertm_tx_window_size - 1, req_seq=0, payload=SAMPLE_PACKET)
        assertThat(cert_channel).emits(
            L2capMatchers.SFrame(s=SupervisoryFunction.REJECT))

        cert_channel.send_s_frame(req_seq=0, p=Poll.POLL)

        assertThat(cert_channel).emits(
            L2capMatchers.SFrame(
                req_seq=1, f=l2cap_packets.Final.POLL_RESPONSE))
        for i in range(1, ertm_tx_window_size):
            cert_channel.send_i_frame(
                tx_seq=i, req_seq=0, payload=SAMPLE_PACKET)
            assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=i + 1))

    def test_handle_duplicate_srej(self):
        """
        L2CAP/ERM/BI-03-C [Handle Duplicate S-Frame [SREJ]]
        Verify the IUT will only retransmit the requested I-frame once after receiving a duplicate SREJ.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0),
            L2capMatchers.IFrame(tx_seq=1),
            L2capMatchers.SFrame(p=Poll.POLL)).inOrder()

        cert_channel.send_s_frame(
            req_seq=0, s=SupervisoryFunction.SELECT_REJECT)
        assertThat(cert_channel).emitsNone(timeout=timedelta(seconds=0.5))

        cert_channel.send_s_frame(
            req_seq=0,
            s=SupervisoryFunction.SELECT_REJECT,
            f=Final.POLL_RESPONSE)
        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=0))

    def test_handle_receipt_rej_and_rr_with_f_set(self):
        """
        L2CAP/ERM/BI-04-C [Handle Receipt of S-Frame [REJ] and S-Frame [RR, F=1] that Both Require Retransmission of the Same I-Frames]
        Verify the IUT will only retransmit the requested I-frames once after receiving an S-frame [REJ]
        followed by an S-frame [RR] with the Final bit set that indicates the same I-frames should be
        retransmitted.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0),
            L2capMatchers.IFrame(tx_seq=1),
            L2capMatchers.SFrame(p=l2cap_packets.Poll.POLL)).inOrder()

        cert_channel.send_s_frame(req_seq=0, s=SupervisoryFunction.REJECT)
        assertThat(cert_channel).emitsNone(timeout=timedelta(seconds=0.5))

        # Send RR with F set
        cert_channel.send_s_frame(
            req_seq=0, s=SupervisoryFunction.REJECT, f=Final.POLL_RESPONSE)
        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=0))
        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=1))

    def test_handle_rej_and_i_frame_with_f_set(self):
        """
        L2CAP/ERM/BI-05-C [Handle receipt of S-Frame [REJ] and I-Frame [F=1] that Both Require Retransmission of the Same I-Frames]
        Verify the IUT will only retransmit the requested I-frames once after receiving an S-frame [REJ]
        followed by an I-frame with the Final bit set that indicates the same I-frames should be retransmitted.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        (dut_channel, cert_channel) = self._open_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        dut_channel.send(b'abc')
        dut_channel.send(b'abc')
        assertThat(cert_channel).emits(
            L2capMatchers.IFrame(tx_seq=0),
            L2capMatchers.IFrame(tx_seq=1),
            L2capMatchers.SFrame(p=l2cap_packets.Poll.POLL)).inOrder()

        # Send SREJ with F not set
        cert_channel.send_s_frame(
            req_seq=0, s=SupervisoryFunction.SELECT_REJECT)
        assertThat(cert_channel).emitsNone(timeout=timedelta(seconds=0.5))

        cert_channel.send_i_frame(
            tx_seq=0, req_seq=0, f=Final.POLL_RESPONSE, payload=SAMPLE_PACKET)

        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=0))
        assertThat(cert_channel).emits(L2capMatchers.IFrame(tx_seq=1))

    def test_initiated_configuration_request_ertm(self):
        """
        L2CAP/CMC/BV-01-C [IUT Initiated Configuration of Enhanced Retransmission Mode]
        Verify the IUT can send a Configuration Request command containing the F&EC option that specifies
        Enhanced Retransmission Mode.
        """
        self._setup_link_from_cert()
        self.cert_l2cap.turn_on_ertm()

        self._open_unvalidated_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)

        # TODO: Fix this test. It doesn't work so far with PDL struct

        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationRequest())
        asserts.skip("Struct not working")

    def test_respond_configuration_request_ertm(self):
        """
        L2CAP/CMC/BV-02-C [Lower Tester Initiated Configuration of Enhanced Retransmission Mode]
        Verify the IUT can accept a Configuration Request from the Lower Tester containing an F&EC option
        that specifies Enhanced Retransmission Mode.
        """
        asserts.skip("ConfigurationResponseView Not working")
        self._setup_link_from_cert()
        psm = 1
        scid = 0x0101
        self.retransmission_mode = RetransmissionFlowControlMode.ERTM
        self.dut.l2cap.SetDynamicChannel(
            l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                psm=psm, retransmission_mode=self.retransmission_mode))

        open_channel = l2cap_packets.ConnectionRequestBuilder(1, psm, scid)
        open_channel_l2cap = l2cap_packets.BasicFrameBuilder(1, open_channel)
        self.cert_send_b_frame(open_channel_l2cap)

        # TODO: Verify that the type should be ERTM
        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationResponse())

    def test_respond_not_support_ertm_when_using_mandatory_ertm(self):
        """
        L2CAP/CMC/BV-12-C
        """
        self._setup_link_from_cert()
        dut_channel_future = self.dut_l2cap.connect_dynamic_channel_to_cert(
            psm=0x33, mode=RetransmissionFlowControlMode.ERTM)
        assertThat(self.cert_l2cap.get_control_channel()).emitsNone(
            L2capMatchers.ConnectionRequest(0x33))

    def test_config_respond_basic_mode_when_using_mandatory_ertm(self):
        """
        L2CAP/CMC/BI-01-C
        """
        self._setup_link_from_cert()
        self.cert_l2cap.reply_with_basic_mode()
        (dut_channel, cert_channel) = self._open_unvalidated_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)
        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationRequest())
        cert_channel.verify_disconnect_request()

    def test_config_request_basic_mode_when_using_mandatory_ertm(self):
        """
        L2CAP/CMC/BI-02-C
        """
        self._setup_link_from_cert()
        self.cert_l2cap.reply_with_nothing()
        self.cert_l2cap.config_with_basic_mode()
        (dut_channel, cert_channel) = self._open_unvalidated_channel(
            scid=0x41, psm=0x33, mode=RetransmissionFlowControlMode.ERTM)
        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.ConfigurationRequest())
        cert_channel.verify_disconnect_request()
