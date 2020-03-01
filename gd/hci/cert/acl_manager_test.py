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

import os
import sys
import logging

from cert.gd_base_test_facade_only import GdFacadeOnlyBaseTestClass
from cert.event_stream import EventStream
from cert.truth import assertThat
from google.protobuf import empty_pb2 as empty_proto
from hci.facade import acl_manager_facade_pb2 as acl_manager_facade
from neighbor.facade import facade_pb2 as neighbor_facade
from hci.facade import controller_facade_pb2 as controller_facade
from hci.facade import facade_pb2 as hci_facade
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import hci_packets
from captures import ReadBdAddrCompleteCapture
from captures import ConnectionCompleteCapture
from captures import ConnectionRequestCapture


class AclManagerTest(GdFacadeOnlyBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='HCI_INTERFACES', cert_module='HCI')

    def enqueue_acl_data(self, handle, pb_flag, b_flag, acl):
        acl_msg = hci_facade.AclMsg(
            handle=int(handle),
            packet_boundary_flag=int(pb_flag),
            broadcast_flag=int(b_flag),
            data=acl)
        self.cert.hci.SendAclData(acl_msg)

    def test_dut_connects(self):
        self.cert.hci.register_for_events(
            hci_packets.EventCode.CONNECTION_REQUEST,
            hci_packets.EventCode.CONNECTION_COMPLETE,
            hci_packets.EventCode.CONNECTION_PACKET_TYPE_CHANGED)

        with self.cert.hci.new_event_stream() as cert_hci_event_stream, \
            EventStream(self.cert.hci.FetchAclPackets(empty_proto.Empty())) as cert_acl_data_stream, \
            EventStream(self.dut.hci_acl_manager.FetchAclData(empty_proto.Empty())) as acl_data_stream:

            # CERT Enables scans and gets its address
            self.cert.hci.send_command_with_complete(
                hci_packets.WriteScanEnableBuilder(
                    hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))

            self.cert.hci.send_command_with_complete(
                hci_packets.ReadBdAddrBuilder())

            read_bd_addr = ReadBdAddrCompleteCapture()
            assertThat(cert_hci_event_stream).emits(read_bd_addr)
            cert_address = read_bd_addr.get().GetBdAddr()

            with EventStream(
                    self.dut.hci_acl_manager.CreateConnection(
                        acl_manager_facade.ConnectionMsg(
                            address_type=int(
                                hci_packets.AddressType.PUBLIC_DEVICE_ADDRESS),
                            address=bytes(cert_address,
                                          'utf8')))) as connection_event_stream:

                # Cert Accepts
                connection_request = ConnectionRequestCapture()
                assertThat(cert_hci_event_stream).emits(connection_request)

                self.cert.hci.send_command_with_status(
                    hci_packets.AcceptConnectionRequestBuilder(
                        connection_request.get().GetBdAddr(),
                        hci_packets.AcceptConnectionRequestRole.REMAIN_SLAVE))

                # Cert gets ConnectionComplete with a handle and sends ACL data
                connection_complete = ConnectionCompleteCapture()
                assertThat(cert_hci_event_stream).emits(connection_complete)
                cert_handle = connection_complete.get().GetConnectionHandle()

                self.enqueue_acl_data(
                    cert_handle, hci_packets.PacketBoundaryFlag.
                    FIRST_AUTOMATICALLY_FLUSHABLE,
                    hci_packets.BroadcastFlag.POINT_TO_POINT,
                    bytes(
                        b'\x26\x00\x07\x00This is just SomeAclData from the Cert'
                    ))

                # DUT gets a connection complete event and sends and receives
                connection_complete = ConnectionCompleteCapture()
                connection_event_stream.assert_event_occurs(connection_complete)
                dut_handle = connection_complete.get().GetConnectionHandle()

                self.dut.hci_acl_manager.SendAclData(
                    acl_manager_facade.AclData(
                        handle=dut_handle,
                        payload=bytes(
                            b'\x29\x00\x07\x00This is just SomeMoreAclData from the DUT'
                        )))

                assertThat(cert_acl_data_stream).emits(
                    lambda packet: b'SomeMoreAclData' in packet.data)
                assertThat(acl_data_stream).emits(
                    lambda packet: b'SomeAclData' in packet.payload)

    def test_cert_connects(self):
        self.cert.hci.register_for_events(
            hci_packets.EventCode.ROLE_CHANGE,
            hci_packets.EventCode.CONNECTION_COMPLETE,
            hci_packets.EventCode.CONNECTION_PACKET_TYPE_CHANGED)

        with self.cert.hci.new_event_stream() as cert_hci_event_stream, \
            EventStream(self.cert.hci.FetchAclPackets(empty_proto.Empty())) as cert_acl_data_stream, \
            EventStream(self.dut.hci_acl_manager.FetchIncomingConnection(empty_proto.Empty())) as incoming_connection_stream, \
            EventStream(self.dut.hci_acl_manager.FetchAclData(empty_proto.Empty())) as acl_data_stream:

            # DUT Enables scans and gets its address
            dut_address = self.dut.hci_controller.GetMacAddressSimple()

            self.dut.neighbor.EnablePageScan(
                neighbor_facade.EnableMsg(enabled=True))

            # Cert connects
            self.cert.hci.send_command_with_status(
                hci_packets.CreateConnectionBuilder(
                    dut_address.decode('utf-8'),
                    0xcc18,  # Packet Type
                    hci_packets.PageScanRepetitionMode.R1,
                    0x0,
                    hci_packets.ClockOffsetValid.INVALID,
                    hci_packets.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH))

            # DUT gets a connection request
            connection_complete = ConnectionCompleteCapture()
            assertThat(incoming_connection_stream).emits(connection_complete)
            dut_handle = connection_complete.get().GetConnectionHandle()

            self.dut.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=dut_handle,
                    payload=bytes(
                        b'\x29\x00\x07\x00This is just SomeMoreAclData from the DUT'
                    )))

            connection_complete = ConnectionCompleteCapture()
            assertThat(cert_hci_event_stream).emits(connection_complete)
            cert_handle = connection_complete.get().GetConnectionHandle()

            self.enqueue_acl_data(
                cert_handle,
                hci_packets.PacketBoundaryFlag.FIRST_AUTOMATICALLY_FLUSHABLE,
                hci_packets.BroadcastFlag.POINT_TO_POINT,
                bytes(
                    b'\x26\x00\x07\x00This is just SomeAclData from the Cert'))

            assertThat(cert_acl_data_stream).emits(
                lambda packet: b'SomeMoreAclData' in packet.data)
            assertThat(acl_data_stream).emits(
                lambda packet: b'SomeAclData' in packet.payload)

    def test_recombination_l2cap_packet(self):
        self.cert.hci.register_for_events(
            hci_packets.EventCode.CONNECTION_REQUEST,
            hci_packets.EventCode.CONNECTION_COMPLETE,
            hci_packets.EventCode.CONNECTION_PACKET_TYPE_CHANGED)

        with self.cert.hci.new_event_stream() as cert_hci_event_stream, \
            EventStream(self.cert.hci.FetchAclPackets(empty_proto.Empty())) as cert_acl_data_stream, \
            EventStream(self.dut.hci_acl_manager.FetchAclData(empty_proto.Empty())) as acl_data_stream:

            # CERT Enables scans and gets its address
            self.cert.hci.send_command_with_complete(
                hci_packets.WriteScanEnableBuilder(
                    hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))

            self.cert.hci.send_command_with_complete(
                hci_packets.ReadBdAddrBuilder())

            read_bd_addr = ReadBdAddrCompleteCapture()
            assertThat(cert_hci_event_stream).emits(read_bd_addr)
            cert_address = read_bd_addr.get().GetBdAddr()

            with EventStream(
                    self.dut.hci_acl_manager.CreateConnection(
                        acl_manager_facade.ConnectionMsg(
                            address_type=int(
                                hci_packets.AddressType.PUBLIC_DEVICE_ADDRESS),
                            address=bytes(cert_address,
                                          'utf8')))) as connection_event_stream:

                # Cert Accepts
                connection_request = ConnectionRequestCapture()
                assertThat(cert_hci_event_stream).emits(connection_request)
                self.cert.hci.send_command_with_status(
                    hci_packets.AcceptConnectionRequestBuilder(
                        connection_request.get().GetBdAddr(),
                        hci_packets.AcceptConnectionRequestRole.REMAIN_SLAVE))

                # Cert gets ConnectionComplete with a handle and sends ACL data
                connection_complete = ConnectionCompleteCapture()
                assertThat(cert_hci_event_stream).emits(connection_complete)
                cert_handle = connection_complete.get().GetConnectionHandle()

                self.enqueue_acl_data(
                    cert_handle, hci_packets.PacketBoundaryFlag.
                    FIRST_AUTOMATICALLY_FLUSHABLE,
                    hci_packets.BroadcastFlag.POINT_TO_POINT,
                    bytes(b'\x06\x00\x07\x00Hello'))
                self.enqueue_acl_data(
                    cert_handle,
                    hci_packets.PacketBoundaryFlag.CONTINUING_FRAGMENT,
                    hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'!'))
                self.enqueue_acl_data(
                    cert_handle, hci_packets.PacketBoundaryFlag.
                    FIRST_AUTOMATICALLY_FLUSHABLE,
                    hci_packets.BroadcastFlag.POINT_TO_POINT,
                    bytes(b'\xe8\x03\x07\x00' + b'Hello' * 200))

                # DUT gets a connection complete event and sends and receives
                connection_complete = ConnectionCompleteCapture()
                connection_event_stream.assert_event_occurs(connection_complete)
                dut_handle = connection_complete.get().GetConnectionHandle()

                assertThat(acl_data_stream).emits(
                    lambda packet: b'Hello!' in packet.payload).then(
                        lambda packet: b'Hello' * 200 in packet.payload)
