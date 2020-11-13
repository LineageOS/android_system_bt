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
from cert.event_stream import FilteringEventStream
from cert.event_stream import IEventStream
from cert.closable import Closable
from cert.closable import safeClose
from cert.captures import HciCaptures
from cert.truth import assertThat
from hal import facade_pb2 as hal_facade
from bluetooth_packets_python3.hci_packets import WriteScanEnableBuilder
from bluetooth_packets_python3.hci_packets import ScanEnable
from bluetooth_packets_python3.hci_packets import AclPacketBuilder
from bluetooth_packets_python3 import RawBuilder
from bluetooth_packets_python3.hci_packets import BroadcastFlag
from bluetooth_packets_python3.hci_packets import PacketBoundaryFlag
from bluetooth_packets_python3 import hci_packets


class PyHalAclConnection(IEventStream):

    def __init__(self, handle, acl_stream, device):
        self.handle = int(handle)
        self.device = device
        self.our_acl_stream = FilteringEventStream(acl_stream, None)

    def send(self, pb_flag, b_flag, data):
        acl = AclPacketBuilder(self.handle, pb_flag, b_flag, RawBuilder(data))
        self.device.hal.SendAcl(hal_facade.AclPacket(payload=bytes(acl.Serialize())))

    def send_first(self, data):
        self.send(PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE, BroadcastFlag.POINT_TO_POINT, bytes(data))

    def get_event_queue(self):
        return self.our_acl_stream.get_event_queue()


class PyHal(Closable):

    def __init__(self, device):
        self.device = device

        self.hci_event_stream = EventStream(self.device.hal.StreamEvents(empty_proto.Empty()))
        self.acl_stream = EventStream(self.device.hal.StreamAcl(empty_proto.Empty()))

        # We don't deal with SCO for now

    def close(self):
        safeClose(self.hci_event_stream)
        safeClose(self.acl_stream)

    def get_hci_event_stream(self):
        return self.hci_event_stream

    def get_acl_stream(self):
        return self.acl_stream

    def send_hci_command(self, command):
        self.device.hal.SendCommand(hal_facade.Command(payload=bytes(command.Serialize())))

    def send_acl(self, handle, pb_flag, b_flag, data):
        acl = AclPacketBuilder(handle, pb_flag, b_flag, RawBuilder(data))
        self.device.hal.SendAcl(hal_facade.AclPacket(payload=bytes(acl.Serialize())))

    def send_acl_first(self, handle, data):
        self.send_acl(handle, PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE, BroadcastFlag.POINT_TO_POINT, data)

    def enable_inquiry_and_page_scan(self):
        self.send_hci_command(WriteScanEnableBuilder(ScanEnable.INQUIRY_AND_PAGE_SCAN))

    def initiate_connection(self, remote_addr):
        self.send_hci_command(
            hci_packets.CreateConnectionBuilder(
                remote_addr if isinstance(remote_addr, str) else remote_addr.decode('utf-8'),
                0xcc18,  # Packet Type
                hci_packets.PageScanRepetitionMode.R1,
                0x0,
                hci_packets.ClockOffsetValid.INVALID,
                hci_packets.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH))

    def accept_connection(self):
        connection_request = HciCaptures.ConnectionRequestCapture()
        assertThat(self.hci_event_stream).emits(connection_request)

        self.send_hci_command(
            hci_packets.AcceptConnectionRequestBuilder(connection_request.get().GetBdAddr(),
                                                       hci_packets.AcceptConnectionRequestRole.REMAIN_PERIPHERAL))
        return self.complete_connection()

    def complete_connection(self):
        connection_complete = HciCaptures.ConnectionCompleteCapture()
        assertThat(self.hci_event_stream).emits(connection_complete)

        handle = connection_complete.get().GetConnectionHandle()
        return PyHalAclConnection(handle, self.acl_stream, self.device)
