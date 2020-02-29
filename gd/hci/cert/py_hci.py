#!/usr/bin/env python3
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

from google.protobuf import empty_pb2 as empty_proto
from cert.event_stream import EventStream
from captures import ReadBdAddrCompleteCapture
from bluetooth_packets_python3 import hci_packets
from cert.truth import assertThat


class PyHci(object):

    def __init__(self, device):
        self.device = device
        self.event_stream = self.device.hci.new_event_stream()
        self.acl_stream = EventStream(
            self.device.hci.FetchAclPackets(empty_proto.Empty()))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.clean_up()
        return traceback is None

    def __del__(self):
        self.clean_up()

    def clean_up(self):
        self.event_stream.shutdown()
        self.acl_stream.shutdown()

    def get_event_stream(self):
        return self.event_stream

    def get_acl_stream(self):
        return self.acl_stream

    def send_command_with_complete(self, command):
        self.device.hci.send_command_with_complete(command)

    def send_command_with_status(self, command):
        self.device.hci.send_command_with_status(command)

    def enable_inquiry_and_page_scan(self):
        self.send_command_with_complete(
            hci_packets.WriteScanEnableBuilder(
                hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))

    def read_own_address(self):
        self.send_command_with_complete(hci_packets.ReadBdAddrBuilder())
        read_bd_addr = ReadBdAddrCompleteCapture()
        assertThat(self.event_stream).emits(read_bd_addr)
        return read_bd_addr.get().GetBdAddr()
