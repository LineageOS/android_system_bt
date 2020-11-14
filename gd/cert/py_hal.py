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
from cert.matchers import HciMatchers
from bluetooth_packets_python3.hci_packets import FilterDuplicates
from bluetooth_packets_python3.hci_packets import LeSetExtendedAdvertisingLegacyParametersBuilder
from bluetooth_packets_python3.hci_packets import LegacyAdvertisingProperties
from bluetooth_packets_python3.hci_packets import PeerAddressType
from bluetooth_packets_python3.hci_packets import AdvertisingFilterPolicy
from bluetooth_packets_python3.hci_packets import LeSetExtendedAdvertisingRandomAddressBuilder
from bluetooth_packets_python3.hci_packets import GapData
from bluetooth_packets_python3.hci_packets import GapDataType
from bluetooth_packets_python3.hci_packets import LeSetExtendedAdvertisingDataBuilder
from bluetooth_packets_python3.hci_packets import Operation
from bluetooth_packets_python3.hci_packets import OwnAddressType
from bluetooth_packets_python3.hci_packets import LeScanningFilterPolicy
from bluetooth_packets_python3.hci_packets import Enable
from bluetooth_packets_python3.hci_packets import FragmentPreference
from bluetooth_packets_python3.hci_packets import LeSetExtendedAdvertisingScanResponseBuilder
from bluetooth_packets_python3.hci_packets import LeSetExtendedAdvertisingEnableBuilder
from bluetooth_packets_python3.hci_packets import LeSetExtendedScanEnableBuilder
from bluetooth_packets_python3.hci_packets import EnabledSet
from bluetooth_packets_python3.hci_packets import OpCode


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


class PyHalAdvertisement(object):

    def __init__(self, handle, py_hal):
        self.handle = handle
        self.py_hal = py_hal

    def set_data(self, complete_name):
        data = GapData()
        data.data_type = GapDataType.COMPLETE_LOCAL_NAME
        data.data = list(bytes(complete_name))
        self.py_hal.send_hci_command(
            LeSetExtendedAdvertisingDataBuilder(self.handle, Operation.COMPLETE_ADVERTISEMENT,
                                                FragmentPreference.CONTROLLER_SHOULD_NOT, [data]))

    def set_scan_response(self, shortened_name):
        data = GapData()
        data.data_type = GapDataType.SHORTENED_LOCAL_NAME
        data.data = list(bytes(shortened_name))
        self.py_hal.send_hci_command(
            LeSetExtendedAdvertisingScanResponseBuilder(self.handle, Operation.COMPLETE_ADVERTISEMENT,
                                                        FragmentPreference.CONTROLLER_SHOULD_NOT, [data]))

    def start(self):
        enabled_set = EnabledSet()
        enabled_set.advertising_handle = self.handle
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.py_hal.send_hci_command(LeSetExtendedAdvertisingEnableBuilder(Enable.ENABLED, [enabled_set]))
        assertThat(self.py_hal.get_hci_event_stream()).emits(
            HciMatchers.CommandComplete(OpCode.LE_SET_EXTENDED_ADVERTISING_ENABLE))

    def stop(self):
        enabled_set = EnabledSet()
        enabled_set.advertising_handle = self.handle
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.py_hal.send_hci_command(LeSetExtendedAdvertisingEnableBuilder(Enable.DISABLED, [enabled_set]))
        assertThat(self.py_hal.get_hci_event_stream()).emits(
            HciMatchers.CommandComplete(OpCode.LE_SET_EXTENDED_ADVERTISING_ENABLE))


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

    def read_own_address(self):
        self.send_hci_command(hci_packets.ReadBdAddrBuilder())
        read_bd_addr = HciCaptures.ReadBdAddrCompleteCapture()
        assertThat(self.hci_event_stream).emits(read_bd_addr)
        return read_bd_addr.get().GetBdAddr()

    def reset(self):
        self.send_hci_command(hci_packets.ResetBuilder())
        assertThat(self.hci_event_stream).emits(HciMatchers.CommandComplete(OpCode.RESET))

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

    def initiate_le_connection(self, remote_addr):
        phy_scan_params = hci_packets.LeCreateConnPhyScanParameters()
        phy_scan_params.scan_interval = 0x60
        phy_scan_params.scan_window = 0x30
        phy_scan_params.conn_interval_min = 0x18
        phy_scan_params.conn_interval_max = 0x28
        phy_scan_params.conn_latency = 0
        phy_scan_params.supervision_timeout = 0x1f4
        phy_scan_params.min_ce_length = 0
        phy_scan_params.max_ce_length = 0
        self.send_hci_command(
            hci_packets.LeExtendedCreateConnectionBuilder(
                hci_packets.InitiatorFilterPolicy.USE_PEER_ADDRESS, hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, remote_addr, 1, [phy_scan_params]))

    def add_to_connect_list(self, remote_addr):
        self.send_hci_command(
            hci_packets.LeAddDeviceToConnectListBuilder(hci_packets.ConnectListAddressType.RANDOM, remote_addr))

    def initiate_le_connection_by_connect_list(self, remote_addr):
        phy_scan_params = hci_packets.LeCreateConnPhyScanParameters()
        phy_scan_params.scan_interval = 0x60
        phy_scan_params.scan_window = 0x30
        phy_scan_params.conn_interval_min = 0x18
        phy_scan_params.conn_interval_max = 0x28
        phy_scan_params.conn_latency = 0
        phy_scan_params.supervision_timeout = 0x1f4
        phy_scan_params.min_ce_length = 0
        phy_scan_params.max_ce_length = 0
        self.send_hci_command(
            hci_packets.LeExtendedCreateConnectionBuilder(
                hci_packets.InitiatorFilterPolicy.USE_CONNECT_LIST, hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, remote_addr, 1, [phy_scan_params]))

    def complete_le_connection(self):
        connection_complete = HciCaptures.LeConnectionCompleteCapture()
        assertThat(self.hci_event_stream).emits(connection_complete)

        handle = connection_complete.get().GetConnectionHandle()
        return PyHalAclConnection(handle, self.acl_stream, self.device)

    def create_advertisement(self,
                             handle,
                             own_address,
                             properties=LegacyAdvertisingProperties.ADV_IND,
                             min_interval=400,
                             max_interval=450,
                             channel_map=7,
                             own_address_type=OwnAddressType.RANDOM_DEVICE_ADDRESS,
                             peer_address_type=PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                             peer_address='00:00:00:00:00:00',
                             filter_policy=AdvertisingFilterPolicy.ALL_DEVICES,
                             tx_power=0xF8,
                             sid=1,
                             scan_request_notification=Enable.DISABLED):

        self.send_hci_command(
            LeSetExtendedAdvertisingLegacyParametersBuilder(handle, properties, min_interval, max_interval, channel_map,
                                                            own_address_type, peer_address_type, peer_address,
                                                            filter_policy, tx_power, sid, scan_request_notification))

        self.send_hci_command(LeSetExtendedAdvertisingRandomAddressBuilder(handle, own_address))
        return PyHalAdvertisement(handle, self)
