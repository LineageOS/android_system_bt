#
#   Copyright 2021 - The Android Open Source Project
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
import logging

from bluetooth_packets_python3 import hci_packets
from cert.event_stream import EventStream
from cert.gd_base_test import GdBaseTestClass
from cert.matchers import HciMatchers, IsoMatchers, L2capMatchers
from cert.metadata import metadata
from cert.py_hci import PyHci
from cert.py_l2cap import PyLeL2cap
from cert.py_le_iso import PyLeIso
from cert.py_le_iso import CisTestParameters
from cert.truth import assertThat
from datetime import timedelta
from facade import common_pb2 as common
from hci.facade import controller_facade_pb2 as controller_facade
from hci.facade import le_advertising_manager_facade_pb2 as le_advertising_facade
from hci.facade import le_initiator_address_facade_pb2 as le_initiator_address_facade
from google.protobuf import empty_pb2 as empty_proto
from neighbor.facade import facade_pb2 as neighbor_facade
from l2cap.le.cert.cert_le_l2cap import CertLeL2cap
from iso.cert.cert_le_iso import CertLeIso

import time
from bluetooth_packets_python3.hci_packets import OpCode


class LeIsoTest(GdBaseTestClass):
    """
        Collection of tests that each sample results from
        different (unique) combinations of io capabilities, authentication requirements, and oob data.
    """

    def setup_class(self):
        super().setup_class(dut_module='L2CAP', cert_module='HCI_INTERFACES')

    def setup_test(self):
        super().setup_test()

        self.dut_l2cap = PyLeL2cap(self.dut)
        self.cert_l2cap = CertLeL2cap(self.cert)
        self.dut_address = common.BluetoothAddressWithType(
            address=common.BluetoothAddress(address=bytes(b'D0:05:04:03:02:01')), type=common.RANDOM_DEVICE_ADDRESS)
        self.cert_address = common.BluetoothAddressWithType(
            address=common.BluetoothAddress(address=bytes(b'C0:11:FF:AA:33:22')), type=common.RANDOM_DEVICE_ADDRESS)
        dut_privacy_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_STATIC_ADDRESS,
            address_with_type=self.dut_address,
            rotation_irk=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            minimum_rotation_time=0,
            maximum_rotation_time=0)
        self.dut_l2cap._device.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(dut_privacy_policy)
        privacy_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_STATIC_ADDRESS,
            address_with_type=self.cert_address,
            rotation_irk=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
            minimum_rotation_time=0,
            maximum_rotation_time=0)
        self.cert_l2cap._device.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(privacy_policy)

        self.dut_iso = PyLeIso(self.dut)
        self.cert_iso = CertLeIso(self.cert)

    def teardown_test(self):
        self.dut_iso.close()
        self.cert_iso.close()

        self.cert_l2cap.close()
        self.dut_l2cap.close()
        super().teardown_test()

    #cert becomes central of connection, dut peripheral
    def _setup_link_from_cert(self):
        # DUT Advertises
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_The_DUT'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)
        create_response = self.dut.hci_le_advertising_manager.CreateAdvertiser(request)
        self.cert_l2cap.connect_le_acl(self.dut_address)

    def _setup_cis_from_cert(self, cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, ft_m_to_s, ft_s_to_m, iso_interval,
                             peripherals_clock_accuracy, packing, framing, max_transport_latency_m_to_s,
                             max_transport_latency_s_to_m, cis_configs):
        self.cert_iso.le_set_cig_parameters_test(cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, ft_m_to_s, ft_s_to_m,
                                                 iso_interval, peripherals_clock_accuracy, packing, framing,
                                                 max_transport_latency_m_to_s, max_transport_latency_s_to_m,
                                                 cis_configs)

        cis_handles = self.cert_iso.wait_le_set_cig_parameters_complete()

        cis_handle = cis_handles[0]

        acl_connection_handle = self.cert_l2cap._le_acl.handle
        self.cert_iso.le_cretate_cis([(cis_handle, acl_connection_handle)])
        dut_cis_stream = self.dut_iso.wait_le_cis_established()
        cert_cis_stream = self.cert_iso.wait_le_cis_established()
        return (dut_cis_stream, cert_cis_stream)

    @metadata(
        pts_test_id="IAL/CIS/UNF/SLA/BV-01-C",
        pts_test_name="connected isochronous stream, unframed data, peripheral role")
    def test_iso_cis_unf_sla_bv_01_c(self):
        """
            Verify that the IUT can send an SDU with length ≤ the Isochronous PDU length.
        """
        cig_id = 0x01
        sdu_interval_m_to_s = 0
        sdu_interval_s_to_m = 0x186a
        ft_m_to_s = 0
        ft_s_to_m = 1
        iso_interval = 0x0A
        peripherals_clock_accuracy = 0
        packing = 0
        framing = 0
        max_transport_latency_m_to_s = 0
        max_transport_latency_s_to_m = 0
        cis_configs = [
            CisTestParameters(
                cis_id=0x01,
                nse=2,
                max_sdu_m_to_s=100,
                max_sdu_s_to_m=100,
                max_pdu_m_to_s=100,
                max_pdu_s_to_m=100,
                phy_m_to_s=0x02,
                phy_s_to_m=0x00,
                bn_m_to_s=0,
                bn_s_to_m=2,
            )
        ]

        self._setup_link_from_cert()
        (dut_cis_stream, cert_cis_stream) = self._setup_cis_from_cert(
            cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, ft_m_to_s, ft_s_to_m, iso_interval,
            peripherals_clock_accuracy, packing, framing, max_transport_latency_m_to_s, max_transport_latency_s_to_m,
            cis_configs)
        dut_cis_stream.send(b'abcdefgh' * 10)
        assertThat(cert_cis_stream).emits(IsoMatchers.Data(b'abcdefgh' * 10))

    @metadata(
        pts_test_id="IAL/CIS/UNF/SLA/BV-25-C",
        pts_test_name="connected isochronous stream, unframed data, peripheral role")
    def test_iso_cis_unf_sla_bv_25_c(self):
        """
            Verify that the IUT can send an SDU with length ≤ the Isochronous PDU length.
        """
        cig_id = 0x01
        sdu_interval_m_to_s = 0x7530
        sdu_interval_s_to_m = 0x7530
        ft_m_to_s = 3
        ft_s_to_m = 2
        iso_interval = 0x18
        peripherals_clock_accuracy = 0
        packing = 0
        framing = 0
        max_transport_latency_m_to_s = 0
        max_transport_latency_s_to_m = 0
        cis_configs = [
            CisTestParameters(
                cis_id=0x01,
                nse=5,
                max_sdu_m_to_s=100,
                max_sdu_s_to_m=100,
                max_pdu_m_to_s=100,
                max_pdu_s_to_m=100,
                phy_m_to_s=0x02,
                phy_s_to_m=0x00,
                bn_m_to_s=3,
                bn_s_to_m=1,
            )
        ]

        self._setup_link_from_cert()
        (dut_cis_stream, cert_cis_stream) = self._setup_cis_from_cert(
            cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, ft_m_to_s, ft_s_to_m, iso_interval,
            peripherals_clock_accuracy, packing, framing, max_transport_latency_m_to_s, max_transport_latency_s_to_m,
            cis_configs)
        dut_cis_stream.send(b'abcdefgh' * 10)
        assertThat(cert_cis_stream).emits(IsoMatchers.Data(b'abcdefgh' * 10))

    @metadata(
        pts_test_id="IAL/CIS/FRA/SLA/BV-03-C",
        pts_test_name="connected isochronous stream, framed data, peripheral role")
    def test_iso_cis_fra_sla_bv_03_c(self):
        """
            Verify that the IUT can send an SDU with length ≤ the Isochronous PDU length.
        """
        cig_id = 0x01
        sdu_interval_m_to_s = 0x0000
        sdu_interval_s_to_m = 0x4e30
        ft_m_to_s = 0
        ft_s_to_m = 2
        iso_interval = 0x14
        peripherals_clock_accuracy = 0
        packing = 0
        framing = 1
        max_transport_latency_m_to_s = 0
        max_transport_latency_s_to_m = 0
        cis_configs = [
            CisTestParameters(
                cis_id=0x01,
                nse=4,
                max_sdu_m_to_s=100,
                max_sdu_s_to_m=100,
                max_pdu_m_to_s=100,
                max_pdu_s_to_m=100,
                phy_m_to_s=0x02,
                phy_s_to_m=0x00,
                bn_m_to_s=0,
                bn_s_to_m=2,
            )
        ]

        self._setup_link_from_cert()
        (dut_cis_stream, cert_cis_stream) = self._setup_cis_from_cert(
            cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, ft_m_to_s, ft_s_to_m, iso_interval,
            peripherals_clock_accuracy, packing, framing, max_transport_latency_m_to_s, max_transport_latency_s_to_m,
            cis_configs)
        dut_cis_stream.send(b'abcdefgh' * 10)
        assertThat(cert_cis_stream).emits(IsoMatchers.Data(b'abcdefgh' * 10))

    @metadata(
        pts_test_id="IAL/CIS/FRA/SLA/BV-26-C",
        pts_test_name="connected isochronous stream, framed data, peripheral role")
    def test_iso_cis_fra_sla_bv_26_c(self):
        """
            Verify that the IUT can send an SDU with length ≤ the Isochronous PDU length.
        """
        cig_id = 0x01
        sdu_interval_m_to_s = 0x14D5
        sdu_interval_s_to_m = 0x14D5
        ft_m_to_s = 1
        ft_s_to_m = 1
        iso_interval = 0x08
        peripherals_clock_accuracy = 0
        packing = 0
        framing = 1
        max_transport_latency_m_to_s = 0
        max_transport_latency_s_to_m = 0
        cis_configs = [
            CisTestParameters(
                cis_id=0x01,
                nse=2,
                max_sdu_m_to_s=100,
                max_sdu_s_to_m=100,
                max_pdu_m_to_s=100,
                max_pdu_s_to_m=100,
                phy_m_to_s=0x02,
                phy_s_to_m=0x00,
                bn_m_to_s=1,
                bn_s_to_m=1,
            )
        ]

        self._setup_link_from_cert()
        (dut_cis_stream, cert_cis_stream) = self._setup_cis_from_cert(
            cig_id, sdu_interval_m_to_s, sdu_interval_s_to_m, ft_m_to_s, ft_s_to_m, iso_interval,
            peripherals_clock_accuracy, packing, framing, max_transport_latency_m_to_s, max_transport_latency_s_to_m,
            cis_configs)
        dut_cis_stream.send(b'abcdefgh' * 10)
        assertThat(cert_cis_stream).emits(IsoMatchers.Data(b'abcdefgh' * 10))
