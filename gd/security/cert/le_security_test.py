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

from bluetooth_packets_python3 import hci_packets
from cert.event_stream import EventStream
from cert.gd_base_test import GdBaseTestClass
from cert.metadata import metadata
from cert.py_le_security import PyLeSecurity
from cert.truth import assertThat
from datetime import timedelta
from facade import common_pb2 as common
from hci.facade import controller_facade_pb2 as controller_facade
from hci.facade import le_advertising_manager_facade_pb2 as le_advertising_facade
from google.protobuf import empty_pb2 as empty_proto
from neighbor.facade import facade_pb2 as neighbor_facade
from security.cert.cert_security import CertSecurity
from security.facade_pb2 import AuthenticationRequirements
from security.facade_pb2 import BondMsgType
from security.facade_pb2 import IoCapabilities
from security.facade_pb2 import OobDataPresent
from security.facade_pb2 import UiMsgType


class LeSecurityTest(GdBaseTestClass):
    """
        Collection of tests that each sample results from
        different (unique) combinations of io capabilities, authentication requirements, and oob data.
    """

    def setup_class(self):
        super().setup_class(dut_module='SECURITY', cert_module='SECURITY')

    def setup_test(self):
        super().setup_test()

        self.dut_security = PyLeSecurity(self.dut)
        self.cert_security = PyLeSecurity(self.cert)

        self.dut_address = common.BluetoothAddressWithType(
            address=common.BluetoothAddress(address=bytes(b'DD:05:04:03:02:01')), type=common.RANDOM_DEVICE_ADDRESS)
        self.dut.security.SetLeInitiatorAddress(self.dut_address)
        self.cert_address = common.BluetoothAddressWithType(
            address=common.BluetoothAddress(address=bytes(b'C5:11:FF:AA:33:22')), type=common.RANDOM_DEVICE_ADDRESS)
        self.cert.security.SetLeInitiatorAddress(self.cert_address)

    def teardown_test(self):
        self.dut_security.close()
        self.cert_security.close()
        super().teardown_test()

    def _prepare_cert_for_connection(self):
        # DUT Advertises
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_The_CERT'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            random_address=self.cert_address.address,
            interval_min=512,
            interval_max=768,
            event_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            address_type=common.RANDOM_DEVICE_ADDRESS,
            peer_address_type=common.PUBLIC_DEVICE_ADDRESS,
            peer_address=common.BluetoothAddress(address=bytes(b'00:00:00:00:00:00')),
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)
        create_response = self.cert.hci_le_advertising_manager.CreateAdvertiser(request)

    @metadata(pts_test_id="SM/MAS/PROT/BV-01-C", pts_test_name="SMP Time Out – IUT Initiator")
    def test_le_smp_timeout_iut_initiator(self):
        """
            Verify that the IUT handles the lack of pairing response after 30 seconds when acting as initiator.
        """
        self._prepare_cert_for_connection()
        self.dut.security.CreateBondLe(self.cert_address)
        self.dut_security.wait_for_bond_event(
            expected_bond_event=BondMsgType.DEVICE_BOND_FAILED, timeout=timedelta(seconds=35))
