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
from cert.py_l2cap import PyL2cap
from cert.py_acl_manager import PyAclManager
from cert.matchers import L2capMatchers
from facade import common_pb2 as common
from facade import rootservice_pb2 as facade_rootservice
from google.protobuf import empty_pb2 as empty_proto
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from neighbor.facade import facade_pb2 as neighbor_facade
from hci.facade import acl_manager_facade_pb2 as acl_manager_facade
from hci.facade import le_advertising_manager_facade_pb2 as le_advertising_facade
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import hci_packets, l2cap_packets
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

        self.dut_l2cap = PyL2cap(self.dut)
        self.cert_l2cap = CertLeL2cap(self.cert)

    def teardown_test(self):
        self.cert_l2cap.close()
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

    def _open_unvalidated_channel(self,
                                  signal_id=1,
                                  scid=0x0101,
                                  psm=0x33,
                                  use_ertm=False):

        dut_channel = self.dut_l2cap.open_credit_based_flow_control_channel(psm)
        cert_channel = self.cert_l2cap.open_channel(signal_id, psm, scid)

        return (dut_channel, cert_channel)

    def test_open_unvalidated_channel(self):
        self._setup_link_from_cert()
        self._open_unvalidated_channel()
