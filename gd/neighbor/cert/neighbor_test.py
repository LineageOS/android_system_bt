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

from datetime import timedelta

from cert.gd_base_test import GdBaseTestClass
from cert.matchers import HciMatchers, NeighborMatchers
from cert.py_hci import PyHci
from cert.truth import assertThat
from neighbor.cert.py_neighbor import PyNeighbor
from neighbor.facade import facade_pb2 as neighbor_facade
from bluetooth_packets_python3 import hci_packets
from bluetooth_packets_python3.hci_packets import OpCode


class NeighborTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='HCI_INTERFACES', cert_module='HCI')

    def setup_test(self):
        super().setup_test()
        self.cert_hci = PyHci(self.cert, acl_streaming=True)
        self.cert_hci.send_command(hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))
        self.cert_name = b'Im_A_Cert'
        self.cert_address = self.cert_hci.read_own_address()
        self.cert_name += b'@' + self.cert_address.encode('utf8')
        self.dut_neighbor = PyNeighbor(self.dut)

    def teardown_test(self):
        self.cert_hci.close()
        super().teardown_test()

    def _set_name(self):
        padded_name = self.cert_name
        while len(padded_name) < 248:
            padded_name = padded_name + b'\0'
        self.cert_hci.send_command(hci_packets.WriteLocalNameBuilder(padded_name))

        assertThat(self.cert_hci.get_event_stream()).emits(HciMatchers.CommandComplete(OpCode.WRITE_LOCAL_NAME))

    def test_inquiry_from_dut(self):
        inquiry_msg = neighbor_facade.InquiryMsg(
            inquiry_mode=neighbor_facade.DiscoverabilityMode.GENERAL,
            result_mode=neighbor_facade.ResultMode.STANDARD,
            length_1_28s=3,
            max_results=0)
        session = self.dut_neighbor.set_inquiry_mode(inquiry_msg)
        self.cert_hci.send_command(hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))
        assertThat(session).emits(NeighborMatchers.InquiryResult(self.cert_address), timeout=timedelta(seconds=10))

    def test_inquiry_rssi_from_dut(self):
        inquiry_msg = neighbor_facade.InquiryMsg(
            inquiry_mode=neighbor_facade.DiscoverabilityMode.GENERAL,
            result_mode=neighbor_facade.ResultMode.RSSI,
            length_1_28s=6,
            max_results=0)
        session = self.dut_neighbor.set_inquiry_mode(inquiry_msg)
        self.cert_hci.send_command(hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))
        assertThat(session).emits(
            NeighborMatchers.InquiryResultwithRssi(self.cert_address), timeout=timedelta(seconds=10))

    def test_inquiry_extended_from_dut(self):
        self._set_name()
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(self.cert_name))
        gap_data = list([gap_name])

        self.cert_hci.send_command(
            hci_packets.WriteExtendedInquiryResponseBuilder(hci_packets.FecRequired.NOT_REQUIRED, gap_data))
        inquiry_msg = neighbor_facade.InquiryMsg(
            inquiry_mode=neighbor_facade.DiscoverabilityMode.GENERAL,
            result_mode=neighbor_facade.ResultMode.EXTENDED,
            length_1_28s=8,
            max_results=0)
        session = self.dut_neighbor.set_inquiry_mode(inquiry_msg)
        self.cert_hci.send_command(hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))
        assertThat(session).emits(
            NeighborMatchers.ExtendedInquiryResult(self.cert_address), timeout=timedelta(seconds=10))

    def test_remote_name(self):
        self._set_name()
        session = self.dut_neighbor.get_remote_name(self.cert_address)
        session.verify_name(self.cert_name)
