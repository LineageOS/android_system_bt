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
from bluetooth_packets_python3 import hci_packets
from cert.truth import assertThat
from hci.facade import facade_pb2 as hci_facade


class PyHciAclConnection(IEventStream):

    def __init__(self, handle, acl_stream, device):
        self.handle = int(handle)
        self.device = device
        # todo, handle we got is 0, so doesn't match - fix before enabling filtering
        self.our_acl_stream = FilteringEventStream(acl_stream, None)

    def send(self, pb_flag, b_flag, data):
        acl_msg = hci_facade.AclPacket(
            handle=self.handle, packet_boundary_flag=int(pb_flag), broadcast_flag=int(b_flag), data=data)
        self.device.hci.SendAcl(acl_msg)

    def send_first(self, data):
        self.send(hci_packets.PacketBoundaryFlag.FIRST_AUTOMATICALLY_FLUSHABLE,
                  hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(data))

    def send_continuing(self, data):
        self.send(hci_packets.PacketBoundaryFlag.CONTINUING_FRAGMENT, hci_packets.BroadcastFlag.POINT_TO_POINT,
                  bytes(data))

    def get_event_queue(self):
        return self.our_acl_stream.get_event_queue()


class PyHci(Closable):

    event_stream = None
    le_event_stream = None
    acl_stream = None

    def __init__(self, device, acl_streaming=False):
        """
            If you are planning on personally using the ACL data stream
            coming from HCI, specify acl_streaming=True. You probably only
            want this if you are testing HCI itself.
        """
        self.device = device
        self.event_stream = EventStream(self.device.hci.StreamEvents(empty_proto.Empty()))
        self.le_event_stream = EventStream(self.device.hci.StreamLeSubevents(empty_proto.Empty()))
        if acl_streaming:
            self.register_for_events(hci_packets.EventCode.ROLE_CHANGE, hci_packets.EventCode.CONNECTION_REQUEST,
                                     hci_packets.EventCode.CONNECTION_COMPLETE,
                                     hci_packets.EventCode.CONNECTION_PACKET_TYPE_CHANGED)
            self.acl_stream = EventStream(self.device.hci.StreamAcl(empty_proto.Empty()))

    def close(self):
        safeClose(self.event_stream)
        safeClose(self.le_event_stream)
        safeClose(self.acl_stream)

    def get_event_stream(self):
        return self.event_stream

    def get_le_event_stream(self):
        return self.le_event_stream

    def get_raw_acl_stream(self):
        if self.acl_stream is None:
            raise Exception("Please construct '%s' with acl_streaming=True!" % self.__class__.__name__)
        return self.acl_stream

    def register_for_events(self, *event_codes):
        for event_code in event_codes:
            self.device.hci.RequestEvent(hci_facade.EventRequest(code=int(event_code)))

    def register_for_le_events(self, *event_codes):
        for event_code in event_codes:
            self.device.hci.RequestLeSubevent(hci_facade.EventRequest(code=int(event_code)))

    def send_command_with_complete(self, command):
        self.device.hci.SendCommandWithComplete(hci_facade.Command(payload=bytes(command.Serialize())))

    def send_command_with_status(self, command):
        self.device.hci.SendCommandWithStatus(hci_facade.Command(payload=bytes(command.Serialize())))

    def enable_inquiry_and_page_scan(self):
        self.send_command_with_complete(
            hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))

    def read_own_address(self):
        self.send_command_with_complete(hci_packets.ReadBdAddrBuilder())
        read_bd_addr = HciCaptures.ReadBdAddrCompleteCapture()
        assertThat(self.event_stream).emits(read_bd_addr)
        return read_bd_addr.get().GetBdAddr()

    def initiate_connection(self, remote_addr):
        self.send_command_with_status(
            hci_packets.CreateConnectionBuilder(
                remote_addr if isinstance(remote_addr, str) else remote_addr.decode('utf-8'),
                0xcc18,  # Packet Type
                hci_packets.PageScanRepetitionMode.R1,
                0x0,
                hci_packets.ClockOffsetValid.INVALID,
                hci_packets.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH))

    def accept_connection(self):
        connection_request = HciCaptures.ConnectionRequestCapture()
        assertThat(self.event_stream).emits(connection_request)

        self.send_command_with_status(
            hci_packets.AcceptConnectionRequestBuilder(connection_request.get().GetBdAddr(),
                                                       hci_packets.AcceptConnectionRequestRole.REMAIN_PERIPHERAL))
        return self.complete_connection()

    def complete_connection(self):
        connection_complete = HciCaptures.ConnectionCompleteCapture()
        assertThat(self.event_stream).emits(connection_complete)

        handle = connection_complete.get().GetConnectionHandle()
        if self.acl_stream is None:
            raise Exception("Please construct '%s' with acl_streaming=True!" % self.__class__.__name__)
        return PyHciAclConnection(handle, self.acl_stream, self.device)
