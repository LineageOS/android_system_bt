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
import logging

from cert.gd_base_test import GdBaseTestClass
from cert.event_stream import EventStream
from google.protobuf import empty_pb2 as empty_proto
from facade import rootservice_pb2 as facade_rootservice
from hci.facade import hci_facade_pb2 as hci_facade
from hci.facade import \
  le_advertising_manager_facade_pb2 as le_advertising_facade
from bluetooth_packets_python3 import hci_packets
from facade import common_pb2 as common
from cert.py_hci import PyHci
from cert.truth import assertThat


class LeAdvertisingManagerTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='HCI_INTERFACES', cert_module='HCI')

    def setup_test(self):
        super().setup_test()
        self.cert_hci = PyHci(self.cert, acl_streaming=True)

    def teardown_test(self):
        self.cert_hci.close()
        super().teardown_test()

    def test_le_ad_scan_dut_advertises(self):
        self.cert_hci.register_for_le_events(hci_packets.SubeventCode.ADVERTISING_REPORT,
                                             hci_packets.SubeventCode.EXTENDED_ADVERTISING_REPORT)

        # CERT Scans
        self.cert_hci.send_command(hci_packets.LeSetRandomAddressBuilder('0C:05:04:03:02:01'))
        scan_parameters = hci_packets.PhyScanParameters()
        scan_parameters.le_scan_type = hci_packets.LeScanType.ACTIVE
        scan_parameters.le_scan_interval = 40
        scan_parameters.le_scan_window = 20
        self.cert_hci.send_command(
            hci_packets.LeSetExtendedScanParametersBuilder(hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                                                           hci_packets.LeScanningFilterPolicy.ACCEPT_ALL, 1,
                                                           [scan_parameters]))
        self.cert_hci.send_command(
            hci_packets.LeSetExtendedScanEnableBuilder(hci_packets.Enable.ENABLED,
                                                       hci_packets.FilterDuplicates.DISABLED, 0, 0))

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

        assertThat(self.cert_hci.get_le_event_stream()).emits(lambda packet: b'Im_The_DUT' in packet.payload)

        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.dut.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        self.cert_hci.send_command(
            hci_packets.LeSetScanEnableBuilder(hci_packets.Enable.DISABLED, hci_packets.Enable.DISABLED))
