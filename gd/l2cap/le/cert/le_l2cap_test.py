#
#   Copyright 2020 - The Android Open Source Project
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
from cert.py_l2cap import PyLeL2cap
from cert.py_acl_manager import PyAclManager
from cert.matchers import L2capMatchers
from facade import common_pb2 as common
from facade import rootservice_pb2 as facade_rootservice
from google.protobuf import empty_pb2 as empty_proto
from l2cap.le import facade_pb2 as l2cap_facade_pb2
from neighbor.facade import facade_pb2 as neighbor_facade
from hci.facade import acl_manager_facade_pb2 as acl_manager_facade
from hci.facade import le_advertising_manager_facade_pb2 as le_advertising_facade
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import hci_packets, l2cap_packets
from bluetooth_packets_python3.l2cap_packets import LeCreditBasedConnectionResponseResult
from l2cap.le.cert.cert_le_l2cap import CertLeL2cap

# Assemble a sample packet. TODO: Use RawBuilder
SAMPLE_PACKET = l2cap_packets.CommandRejectNotUnderstoodBuilder(1)


class LeL2capTest(GdFacadeOnlyBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='L2CAP', cert_module='HCI_INTERFACES')

    def setup_test(self):
        super().setup_test()

        self.dut.address = self.dut.hci_controller.GetMacAddressSimple()
        self.cert.address = self.cert.controller_read_only_property.ReadLocalAddress(
            empty_proto.Empty()).address
        self.cert_address = common.BluetoothAddress(address=self.cert.address)

        self.dut_l2cap = PyLeL2cap(self.dut)
        self.cert_l2cap = CertLeL2cap(self.cert)

    def teardown_test(self):
        self.cert_l2cap.close()
        self.dut_l2cap.close()
        super().teardown_test()

    def _setup_link_from_cert(self):
        # DUT Advertises
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_The_DUT'))
        gap_data = le_advertising_facade.GapDataMsg(
            data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            random_address=common.BluetoothAddress(
                address=bytes(b'0D:05:04:03:02:01')),
            interval_min=512,
            interval_max=768,
            event_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            address_type=common.RANDOM_DEVICE_ADDRESS,
            peer_address_type=common.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
            peer_address=common.BluetoothAddress(
                address=bytes(b'A6:A5:A4:A3:A2:A1')),
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.
            ALL_DEVICES)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)
        create_response = self.dut.hci_le_advertising_manager.CreateAdvertiser(
            request)
        self.cert_l2cap.connect_le_acl(bytes(b'0D:05:04:03:02:01'))

    def _open_channel_from_cert(self,
                                signal_id=1,
                                scid=0x0101,
                                psm=0x33,
                                mtu=1000,
                                mps=100,
                                initial_credit=6):

        dut_channel = self.dut_l2cap.register_coc(psm)
        cert_channel = self.cert_l2cap.open_channel(signal_id, psm, scid, mtu,
                                                    mps, initial_credit)

        return (dut_channel, cert_channel)

    def _open_channel_from_dut(self, psm=0x33):
        response_future = self.dut_l2cap.connect_coc_to_cert(psm)
        cert_channel = self.cert_l2cap.verify_and_respond_open_channel_from_remote(
            psm)
        dut_channel = response_future.get_channel()
        return (dut_channel, cert_channel)

    def test_segmentation(self):
        """
        L2CAP/COS/CFC/BV-01-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_cert(
            mtu=1000, mps=102)
        dut_channel.send(b'hello' * 20 + b'world')
        # The first LeInformation packet contains 2 bytes of SDU size.
        # The packet is divided into first 100 bytes from 'hellohello....'
        # and remaining 5 bytes 'world'
        assertThat(cert_channel).emits(
            L2capMatchers.FirstLeIFrame(b'hello' * 20, sdu_size=105),
            L2capMatchers.Data(b'world')).inOrder()

    def test_no_segmentation(self):
        """
        L2CAP/COS/CFC/BV-02-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_cert(
            mtu=1000, mps=202)
        dut_channel.send(b'hello' * 40)
        assertThat(cert_channel).emits(
            L2capMatchers.FirstLeIFrame(b'hello' * 40, sdu_size=200))

    def test_reassembling(self):
        """
        L2CAP/COS/CFC/BV-03-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_cert()
        sdu_size_for_two_sample_packet = 12
        cert_channel.send_first_le_i_frame(sdu_size_for_two_sample_packet,
                                           SAMPLE_PACKET)
        cert_channel.send(SAMPLE_PACKET)
        assertThat(dut_channel).emits(
            L2capMatchers.PacketPayloadRawData(b'\x01\x01\x02\x00\x00\x00' * 2))

    def test_data_receiving(self):
        """
        L2CAP/COS/CFC/BV-04-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_cert()
        cert_channel.send_first_le_i_frame(6, SAMPLE_PACKET)
        assertThat(dut_channel).emits(
            L2capMatchers.PacketPayloadRawData(b'\x01\x01\x02\x00\x00\x00'))

    def test_multiple_channels_with_interleaved_data_streams(self):
        """
        L2CAP/COS/CFC/BV-05-C
        """
        self._setup_link_from_cert()
        (dut_channel_x, cert_channel_x) = self._open_channel_from_cert(
            signal_id=1, scid=0x0103, psm=0x33)
        (dut_channel_y, cert_channel_y) = self._open_channel_from_cert(
            signal_id=2, scid=0x0105, psm=0x35)
        (dut_channel_z, cert_channel_z) = self._open_channel_from_cert(
            signal_id=3, scid=0x0107, psm=0x37)
        cert_channel_y.send_first_le_i_frame(6, SAMPLE_PACKET)
        cert_channel_z.send_first_le_i_frame(6, SAMPLE_PACKET)
        cert_channel_y.send_first_le_i_frame(6, SAMPLE_PACKET)
        cert_channel_z.send_first_le_i_frame(6, SAMPLE_PACKET)
        cert_channel_y.send_first_le_i_frame(6, SAMPLE_PACKET)
        # TODO: We should assert two events in order, but it got stuck
        assertThat(dut_channel_y).emits(
            L2capMatchers.PacketPayloadRawData(b'\x01\x01\x02\x00\x00\x00'),
            at_least_times=3)
        assertThat(dut_channel_z).emits(
            L2capMatchers.PacketPayloadRawData(b'\x01\x01\x02\x00\x00\x00'),
            L2capMatchers.PacketPayloadRawData(
                b'\x01\x01\x02\x00\x00\x00')).inOrder()
        cert_channel_z.send_first_le_i_frame(6, SAMPLE_PACKET)
        assertThat(dut_channel_z).emits(
            L2capMatchers.PacketPayloadRawData(b'\x01\x01\x02\x00\x00\x00'))

    def test_reject_unknown_command_in_le_sigling_channel(self):
        """
        L2CAP/LE/REJ/BI-01-C
        """
        self._setup_link_from_cert()
        self.cert_l2cap.get_control_channel().send(
            l2cap_packets.InformationRequestBuilder(
                2, l2cap_packets.InformationRequestInfoType.
                EXTENDED_FEATURES_SUPPORTED))
        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.LeCommandReject())

    def test_credit_based_connection_request_unsupported_le_psm(self):
        """
        L2CAP/LE/CFC/BV-05-C
        """
        self._setup_link_from_cert()
        self.cert_l2cap.get_control_channel().send(
            l2cap_packets.LeCreditBasedConnectionRequestBuilder(
                1, 0x34, 0x0101, 2000, 1000, 1000))
        assertThat(self.cert_l2cap.get_control_channel()).emits(
            L2capMatchers.CreditBasedConnectionResponse(
                0x0101,
                result=LeCreditBasedConnectionResponseResult.
                LE_PSM_NOT_SUPPORTED))

    def test_credit_exchange_receiving_incremental_credits(self):
        """
        L2CAP/LE/CFC/BV-06-C
        """
        self._setup_link_from_cert()
        (dut_channel,
         cert_channel) = self._open_channel_from_cert(initial_credit=0)
        for _ in range(4):
            dut_channel.send(b'hello')
        cert_channel.send_credits(1)
        assertThat(cert_channel).emits(
            L2capMatchers.FirstLeIFrame(b'hello', sdu_size=5))
        cert_channel.send_credits(1)
        assertThat(cert_channel).emits(
            L2capMatchers.FirstLeIFrame(b'hello', sdu_size=5))
        cert_channel.send_credits(2)
        assertThat(cert_channel).emits(
            L2capMatchers.FirstLeIFrame(b'hello', sdu_size=5),
            L2capMatchers.FirstLeIFrame(b'hello', sdu_size=5))

    def test_le_credit_based_connection_request_legacy_peer(self):
        """
        L2CAP/LE/CFC/BV-01-C
        """
        self._setup_link_from_cert()
        response_future = self.dut_l2cap.connect_coc_to_cert(psm=0x33)
        self.cert_l2cap.verify_and_reject_open_channel_from_remote(psm=0x33)
        assertThat(response_future.get_status()).isNotEqualTo(
            LeCreditBasedConnectionResponseResult.SUCCESS)

    def test_le_credit_based_connection_request_on_supported_le_psm(self):
        """
        L2CAP/LE/CFC/BV-02-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_dut()
        cert_channel.send_first_le_i_frame(6, SAMPLE_PACKET)
        assertThat(dut_channel).emits(
            L2capMatchers.PacketPayloadRawData(b'\x01\x01\x02\x00\x00\x00'))

    def test_credit_based_connection_response_on_supported_le_psm(self):
        """
        L2CAP/LE/CFC/BV-03-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_cert()
        dut_channel.send(b'hello')
        assertThat(cert_channel).emits(
            L2capMatchers.FirstLeIFrame(b'hello', sdu_size=5))

    def test_credit_based_connection_request_on_an_unsupported_le_psm(self):
        """
        L2CAP/LE/CFC/BV-04-C
        """
        self._setup_link_from_cert()
        response_future = self.dut_l2cap.connect_coc_to_cert(psm=0x33)
        self.cert_l2cap.verify_and_respond_open_channel_from_remote(
            psm=0x33,
            result=LeCreditBasedConnectionResponseResult.LE_PSM_NOT_SUPPORTED)
        assertThat(response_future.get_status()).isEqualTo(
            LeCreditBasedConnectionResponseResult.LE_PSM_NOT_SUPPORTED)

    def test_credit_exchange_exceed_initial_credits(self):
        """
        L2CAP/LE/CFC/BI-01-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_cert()
        cert_channel.send_credits(65535)
        cert_channel.verify_disconnect_request()

    def test_disconnection_response(self):
        """
        L2CAP/LE/CFC/BV-09-C
        """
        self._setup_link_from_cert()
        (dut_channel, cert_channel) = self._open_channel_from_cert()
        cert_channel.disconnect_and_verify()
