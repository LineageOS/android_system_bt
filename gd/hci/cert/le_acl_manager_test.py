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

from cert.closable import safeClose
from cert.gd_base_test import GdBaseTestClass
from cert.event_stream import EventStream
from cert.truth import assertThat
from cert.py_le_acl_manager import PyLeAclManager
from google.protobuf import empty_pb2 as empty_proto
from facade import common_pb2 as common
from hci.facade import le_acl_manager_facade_pb2 as le_acl_manager_facade
from hci.facade import le_advertising_manager_facade_pb2 as le_advertising_facade
from hci.facade import le_initiator_address_facade_pb2 as le_initiator_address_facade
from hci.facade import facade_pb2 as hci_facade
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import hci_packets


class LeAclManagerTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='HCI_INTERFACES', cert_module='HCI')

    def setup_test(self):
        super().setup_test()
        self.dut_le_acl_manager = PyLeAclManager(self.dut)
        self.cert_hci_le_event_stream = EventStream(self.cert.hci.StreamLeSubevents(empty_proto.Empty()))
        self.cert_acl_data_stream = EventStream(self.cert.hci.StreamAcl(empty_proto.Empty()))

    def teardown_test(self):
        safeClose(self.cert_hci_le_event_stream)
        safeClose(self.cert_acl_data_stream)
        safeClose(self.dut_le_acl_manager)
        super().teardown_test()

    def set_privacy_policy_static(self):
        self.dut_address = b'd0:05:04:03:02:01'
        private_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_STATIC_ADDRESS,
            address_with_type=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=bytes(self.dut_address)), type=common.RANDOM_DEVICE_ADDRESS))
        self.dut.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(private_policy)

    def register_for_event(self, event_code):
        msg = hci_facade.EventRequest(code=int(event_code))
        self.cert.hci.RequestEvent(msg)

    def register_for_le_event(self, event_code):
        msg = hci_facade.EventRequest(code=int(event_code))
        self.cert.hci.RequestLeSubevent(msg)

    def enqueue_hci_command(self, command, expect_complete):
        cmd_bytes = bytes(command.Serialize())
        cmd = hci_facade.Command(payload=cmd_bytes)
        if (expect_complete):
            self.cert.hci.SendCommandWithComplete(cmd)
        else:
            self.cert.hci.SendCommandWithStatus(cmd)

    def enqueue_acl_data(self, handle, pb_flag, b_flag, acl):
        acl_msg = hci_facade.AclPacket(
            handle=int(handle), packet_boundary_flag=int(pb_flag), broadcast_flag=int(b_flag), data=acl)
        self.cert.hci.SendAcl(acl_msg)

    def dut_connects(self, check_address):
        self.register_for_le_event(hci_packets.SubeventCode.CONNECTION_COMPLETE)
        self.register_for_le_event(hci_packets.SubeventCode.ENHANCED_CONNECTION_COMPLETE)

        # Cert Advertises
        advertising_handle = 0
        self.enqueue_hci_command(
            hci_packets.LeSetExtendedAdvertisingLegacyParametersBuilder(
                advertising_handle,
                hci_packets.LegacyAdvertisingProperties.ADV_IND,
                400,
                450,
                7,
                hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                '00:00:00:00:00:00',
                hci_packets.AdvertisingFilterPolicy.ALL_DEVICES,
                0xF8,
                1,  #SID
                hci_packets.Enable.DISABLED  # Scan request notification
            ),
            True)

        self.enqueue_hci_command(
            hci_packets.LeSetExtendedAdvertisingRandomAddressBuilder(advertising_handle, '0C:05:04:03:02:01'), True)

        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_A_Cert'))

        self.enqueue_hci_command(
            hci_packets.LeSetExtendedAdvertisingDataBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_name]), True)

        gap_short_name = hci_packets.GapData()
        gap_short_name.data_type = hci_packets.GapDataType.SHORTENED_LOCAL_NAME
        gap_short_name.data = list(bytes(b'Im_A_C'))

        self.enqueue_hci_command(
            hci_packets.LeSetExtendedAdvertisingScanResponseBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_short_name]), True)

        enabled_set = hci_packets.EnabledSet()
        enabled_set.advertising_handle = advertising_handle
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.enqueue_hci_command(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.ENABLED, [enabled_set]), True)

        self.dut_le_acl = self.dut_le_acl_manager.connect_to_remote(
            remote_addr=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=bytes('0C:05:04:03:02:01', 'utf8')),
                type=int(hci_packets.AddressType.RANDOM_DEVICE_ADDRESS)))

        # Cert gets ConnectionComplete with a handle and sends ACL data
        handle = 0xfff
        address = hci_packets.Address()

        def get_handle(packet):
            packet_bytes = packet.payload
            nonlocal handle
            nonlocal address
            if b'\x3e\x13\x01\x00' in packet_bytes:
                cc_view = hci_packets.LeConnectionCompleteView(
                    hci_packets.LeMetaEventView(
                        hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet_bytes)))))
                handle = cc_view.GetConnectionHandle()
                address = cc_view.GetPeerAddress()
                return True
            if b'\x3e\x13\x0A\x00' in packet_bytes:
                cc_view = hci_packets.LeEnhancedConnectionCompleteView(
                    hci_packets.LeMetaEventView(
                        hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet_bytes)))))
                handle = cc_view.GetConnectionHandle()
                address = cc_view.GetPeerResolvablePrivateAddress()
                return True
            return False

        self.cert_hci_le_event_stream.assert_event_occurs(get_handle)
        self.cert_handle = handle
        dut_address_from_complete = address
        if check_address:
            assertThat(dut_address_from_complete).isEqualTo(self.dut_address.decode())

    def send_receive_and_check(self):
        self.enqueue_acl_data(self.cert_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                              hci_packets.BroadcastFlag.POINT_TO_POINT,
                              bytes(b'\x19\x00\x07\x00SomeAclData from the Cert'))

        self.dut_le_acl.send(b'\x1C\x00\x07\x00SomeMoreAclData from the DUT')
        self.cert_acl_data_stream.assert_event_occurs(lambda packet: b'SomeMoreAclData' in packet.data)
        assertThat(self.dut_le_acl).emits(lambda packet: b'SomeAclData' in packet.payload)

    def test_dut_connects(self):
        self.set_privacy_policy_static()
        self.dut_connects(check_address=True)
        self.send_receive_and_check()

    def test_dut_connects_resolvable_address(self):
        privacy_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_RESOLVABLE_ADDRESS,
            rotation_irk=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
            minimum_rotation_time=7 * 60 * 1000,
            maximum_rotation_time=15 * 60 * 1000)
        self.dut.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(privacy_policy)
        self.dut_connects(check_address=False)
        self.send_receive_and_check()

    def test_dut_connects_non_resolvable_address(self):
        privacy_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_NON_RESOLVABLE_ADDRESS,
            rotation_irk=b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f',
            minimum_rotation_time=8 * 60 * 1000,
            maximum_rotation_time=14 * 60 * 1000)
        self.dut.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(privacy_policy)
        self.dut_connects(check_address=False)
        self.send_receive_and_check()

    def test_dut_connects_public_address(self):
        self.dut.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(
            le_initiator_address_facade.PrivacyPolicy(
                address_policy=le_initiator_address_facade.AddressPolicy.USE_PUBLIC_ADDRESS))
        self.dut_connects(check_address=False)
        self.send_receive_and_check()

    def test_dut_connects_public_address_cancelled(self):
        self.dut.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(
            le_initiator_address_facade.PrivacyPolicy(
                address_policy=le_initiator_address_facade.AddressPolicy.USE_PUBLIC_ADDRESS))
        self.dut_connects(check_address=False)
        self.send_receive_and_check()

    def test_cert_connects(self):
        self.set_privacy_policy_static()
        self.register_for_le_event(hci_packets.SubeventCode.CONNECTION_COMPLETE)

        self.dut_le_acl_manager.listen_for_incoming_connections()

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
            peer_address_type=common.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
            peer_address=common.BluetoothAddress(address=bytes(b'A6:A5:A4:A3:A2:A1')),
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)

        self.dut.hci_le_advertising_manager.CreateAdvertiser(request)

        # Cert Connects
        self.enqueue_hci_command(hci_packets.LeSetRandomAddressBuilder('0C:05:04:03:02:01'), True)
        phy_scan_params = hci_packets.LeCreateConnPhyScanParameters()
        phy_scan_params.scan_interval = 0x60
        phy_scan_params.scan_window = 0x30
        phy_scan_params.conn_interval_min = 0x18
        phy_scan_params.conn_interval_max = 0x28
        phy_scan_params.conn_latency = 0
        phy_scan_params.supervision_timeout = 0x1f4
        phy_scan_params.min_ce_length = 0
        phy_scan_params.max_ce_length = 0
        self.enqueue_hci_command(
            hci_packets.LeExtendedCreateConnectionBuilder(hci_packets.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                                                          hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                                                          hci_packets.AddressType.RANDOM_DEVICE_ADDRESS,
                                                          self.dut_address.decode(), 1, [phy_scan_params]), False)

        # Cert gets ConnectionComplete with a handle and sends ACL data
        handle = 0xfff

        def get_handle(packet):
            packet_bytes = packet.payload
            nonlocal handle
            if b'\x3e\x13\x01\x00' in packet_bytes:
                cc_view = hci_packets.LeConnectionCompleteView(
                    hci_packets.LeMetaEventView(
                        hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet_bytes)))))
                handle = cc_view.GetConnectionHandle()
                return True
            if b'\x3e\x13\x0A\x00' in packet_bytes:
                cc_view = hci_packets.LeEnhancedConnectionCompleteView(
                    hci_packets.LeMetaEventView(
                        hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet_bytes)))))
                handle = cc_view.GetConnectionHandle()
                return True
            return False

        self.cert_hci_le_event_stream.assert_event_occurs(get_handle)
        self.cert_handle = handle

        self.enqueue_acl_data(self.cert_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                              hci_packets.BroadcastFlag.POINT_TO_POINT,
                              bytes(b'\x19\x00\x07\x00SomeAclData from the Cert'))

        # DUT gets a connection complete event and sends and receives
        handle = 0xfff
        self.dut_le_acl = self.dut_le_acl_manager.complete_incoming_connection()

        self.send_receive_and_check()

    def test_recombination_l2cap_packet(self):
        self.set_privacy_policy_static()
        self.dut_connects(check_address=True)

        self.enqueue_acl_data(self.cert_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                              hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'\x06\x00\x07\x00Hello'))
        self.enqueue_acl_data(self.cert_handle, hci_packets.PacketBoundaryFlag.CONTINUING_FRAGMENT,
                              hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'!'))

        assertThat(self.dut_le_acl).emits(lambda packet: b'Hello!' in packet.payload)
