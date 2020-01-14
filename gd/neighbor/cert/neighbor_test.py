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
import logging

sys.path.append(os.environ['ANDROID_BUILD_TOP'] + '/system/bt/gd')

from cert.gd_base_test_facade_only import GdFacadeOnlyBaseTestClass
from cert.event_callback_stream import EventCallbackStream
from cert.event_asserts import EventAsserts
from google.protobuf import empty_pb2 as empty_proto
from facade import rootservice_pb2 as facade_rootservice
from hci.facade import facade_pb2 as hci_facade
from neighbor.facade import facade_pb2 as neighbor_facade
from bluetooth_packets_python3 import hci_packets
import bluetooth_packets_python3 as bt_packets


class NeighborTest(GdFacadeOnlyBaseTestClass):

    def setup_test(self):
        self.cert_device = self.gd_devices[0]
        self.device_under_test = self.gd_devices[1]

        self.device_under_test.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    'HCI_INTERFACES'),))
        self.cert_device.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    'HCI'),))

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice.StopStackRequest())
        self.cert_device.rootservice.StopStack(
            facade_rootservice.StopStackRequest())

    def register_for_event(self, event_code):
        msg = hci_facade.EventCodeMsg(code=int(event_code))
        self.cert_device.hci.RegisterEventHandler(msg)

    def register_for_le_event(self, event_code):
        msg = hci_facade.LeSubeventCodeMsg(code=int(event_code))
        self.cert_device.hci.RegisterLeEventHandler(msg)

    def enqueue_hci_command(self, command, expect_complete):
        cmd_bytes = bytes(command.Serialize())
        cmd = hci_facade.CommandMsg(command=cmd_bytes)
        if (expect_complete):
            self.cert_device.hci.EnqueueCommandWithComplete(cmd)
        else:
            self.cert_device.hci.EnqueueCommandWithStatus(cmd)

    def test_inquiry_from_dut(self):
        self.enqueue_hci_command(
            hci_packets.WriteScanEnableBuilder(
                hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN), True)
        inquiry_msg = neighbor_facade.InquiryMsg(
            inquiry_mode=neighbor_facade.DiscoverabilityMode.GENERAL,
            result_mode=neighbor_facade.ResultMode.STANDARD,
            length_1_28s=3,
            max_results=0)
        with EventCallbackStream(
                self.device_under_test.neighbor.SetInquiryMode(
                    inquiry_msg)) as inquiry_event_stream:
            hci_event_asserts = EventAsserts(inquiry_event_stream)
            hci_event_asserts.assert_event_occurs(
                lambda msg: b'\x02\x0f' in msg.packet
                # Expecting an HCI Event (code 0x02, length 0x0f)
            )

    def test_inquiry_rssi_from_dut(self):
        self.enqueue_hci_command(
            hci_packets.WriteScanEnableBuilder(
                hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN), True)
        inquiry_msg = neighbor_facade.InquiryMsg(
            inquiry_mode=neighbor_facade.DiscoverabilityMode.GENERAL,
            result_mode=neighbor_facade.ResultMode.RSSI,
            length_1_28s=3,
            max_results=0)
        with EventCallbackStream(
                self.device_under_test.neighbor.SetInquiryMode(
                    inquiry_msg)) as inquiry_event_stream:
            hci_event_asserts = EventAsserts(inquiry_event_stream)
            hci_event_asserts.assert_event_occurs(
                lambda msg: b'\x22\x0f' in msg.packet
                # Expecting an HCI Event (code 0x22, length 0x0f)
            )

    def test_inquiry_extended_from_dut(self):
        name_string = b'Im_A_Cert'
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(name_string))
        gap_data = list([gap_name])

        self.enqueue_hci_command(
            hci_packets.WriteExtendedInquiryResponseBuilder(
                hci_packets.FecRequired.NOT_REQUIRED, gap_data), True)
        self.enqueue_hci_command(
            hci_packets.WriteScanEnableBuilder(
                hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN), True)
        inquiry_msg = neighbor_facade.InquiryMsg(
            inquiry_mode=neighbor_facade.DiscoverabilityMode.GENERAL,
            result_mode=neighbor_facade.ResultMode.EXTENDED,
            length_1_28s=3,
            max_results=0)
        with EventCallbackStream(
                self.device_under_test.neighbor.SetInquiryMode(
                    inquiry_msg)) as inquiry_event_stream:
            hci_event_asserts = EventAsserts(inquiry_event_stream)
            hci_event_asserts.assert_event_occurs(
                lambda msg: name_string in msg.packet)
