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
from cert.event_stream import EventStream
from cert.truth import assertThat
from cert.py_hal import PyHal
from google.protobuf import empty_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from hal import facade_pb2 as hal_facade_pb2
from bluetooth_packets_python3 import hci_packets
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3.hci_packets import AclPacketBuilder
from bluetooth_packets_python3 import RawBuilder

_GRPC_TIMEOUT = 10


class SimpleHalTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='HAL', cert_module='HAL')

    def setup_test(self):
        super().setup_test()

        self.dut_hal = PyHal(self.dut)
        self.cert_hal = PyHal(self.cert)

        self.dut_hal.send_hci_command(hci_packets.ResetBuilder())
        self.cert_hal.send_hci_command(hci_packets.ResetBuilder())

    def teardown_test(self):
        self.dut_hal.close()
        self.cert_hal.close()
        super().teardown_test()

    def test_fetch_hci_event(self):
        self.dut_hal.send_hci_command(
            hci_packets.LeAddDeviceToConnectListBuilder(hci_packets.ConnectListAddressType.RANDOM, '0C:05:04:03:02:01'))
        event = hci_packets.LeAddDeviceToConnectListCompleteBuilder(1, hci_packets.ErrorCode.SUCCESS)

        assertThat(self.dut_hal.get_hci_event_stream()).emits(lambda packet: bytes(event.Serialize()) in packet.payload)

    def test_loopback_hci_command(self):
        self.dut_hal.send_hci_command(hci_packets.WriteLoopbackModeBuilder(hci_packets.LoopbackMode.ENABLE_LOCAL))

        command = hci_packets.LeAddDeviceToConnectListBuilder(hci_packets.ConnectListAddressType.RANDOM,
                                                              '0C:05:04:03:02:01')
        self.dut_hal.send_hci_command(command)

        assertThat(
            self.dut_hal.get_hci_event_stream()).emits(lambda packet: bytes(command.Serialize()) in packet.payload)

    def test_inquiry_from_dut(self):
        self.cert_hal.send_hci_command(hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))

        lap = hci_packets.Lap()
        lap.lap = 0x33
        self.dut_hal.send_hci_command(hci_packets.InquiryBuilder(lap, 0x30, 0xff))

        assertThat(self.dut_hal.get_hci_event_stream()).emits(lambda packet: b'\x02\x0f' in packet.payload
                                                              # Expecting an HCI Event (code 0x02, length 0x0f)
                                                             )

    def test_le_ad_scan_cert_advertises(self):
        # DUT scans
        self.dut_hal.send_hci_command(hci_packets.LeSetRandomAddressBuilder('0D:05:04:03:02:01'))
        phy_scan_params = hci_packets.PhyScanParameters()
        phy_scan_params.le_scan_interval = 6553
        phy_scan_params.le_scan_window = 6553
        phy_scan_params.le_scan_type = hci_packets.LeScanType.ACTIVE

        self.dut_hal.send_hci_command(
            hci_packets.LeSetExtendedScanParametersBuilder(hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                                                           hci_packets.LeScanningFilterPolicy.ACCEPT_ALL, 1,
                                                           [phy_scan_params]))
        self.dut_hal.send_hci_command(
            hci_packets.LeSetExtendedScanEnableBuilder(hci_packets.Enable.ENABLED,
                                                       hci_packets.FilterDuplicates.DISABLED, 0, 0))

        # CERT Advertises
        advertising_handle = 0
        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingLegacyParametersBuilder(
                advertising_handle,
                hci_packets.LegacyAdvertisingProperties.ADV_IND,
                512,
                768,
                7,
                hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                'A6:A5:A4:A3:A2:A1',
                hci_packets.AdvertisingFilterPolicy.ALL_DEVICES,
                0x7F,
                0,  # SID
                hci_packets.Enable.DISABLED  # Scan request notification
            ))

        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingRandomAddressBuilder(advertising_handle, '0C:05:04:03:02:01'))

        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_A_Cert'))

        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingDataBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_name]))
        enabled_set = hci_packets.EnabledSet()
        enabled_set.advertising_handle = advertising_handle
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.ENABLED, [enabled_set]))

        assertThat(self.dut_hal.get_hci_event_stream()).emits(lambda packet: b'Im_A_Cert' in packet.payload)

        # Disable Advertising
        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.DISABLED, [enabled_set]))

        # Disable Scanning
        self.dut_hal.send_hci_command(
            hci_packets.LeSetExtendedScanEnableBuilder(hci_packets.Enable.ENABLED,
                                                       hci_packets.FilterDuplicates.DISABLED, 0, 0))

    def test_le_connection_dut_advertises(self):
        # Cert Connects
        self.cert_hal.send_hci_command(hci_packets.LeSetRandomAddressBuilder('0C:05:04:03:02:01'))
        phy_scan_params = hci_packets.LeCreateConnPhyScanParameters()
        phy_scan_params.scan_interval = 0x60
        phy_scan_params.scan_window = 0x30
        phy_scan_params.conn_interval_min = 0x18
        phy_scan_params.conn_interval_max = 0x28
        phy_scan_params.conn_latency = 0
        phy_scan_params.supervision_timeout = 0x1f4
        phy_scan_params.min_ce_length = 0
        phy_scan_params.max_ce_length = 0
        self.cert_hal.send_hci_command(
            hci_packets.LeExtendedCreateConnectionBuilder(
                hci_packets.InitiatorFilterPolicy.USE_PEER_ADDRESS, hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, '0D:05:04:03:02:01', 1, [phy_scan_params]))

        # DUT Advertises
        advertising_handle = 0
        self.dut_hal.send_hci_command(
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
            ))

        self.dut_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingRandomAddressBuilder(advertising_handle, '0D:05:04:03:02:01'))

        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_The_DUT'))

        self.dut_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingDataBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_name]))

        gap_short_name = hci_packets.GapData()
        gap_short_name.data_type = hci_packets.GapDataType.SHORTENED_LOCAL_NAME
        gap_short_name.data = list(bytes(b'Im_The_D'))

        self.dut_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingScanResponseBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_short_name]))

        enabled_set = hci_packets.EnabledSet()
        enabled_set.advertising_handle = advertising_handle
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.dut_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.ENABLED, [enabled_set]))

        conn_handle = 0xfff

        def payload_handle(packet):
            packet_bytes = packet.payload
            if b'\x3e\x13\x01\x00' in packet_bytes:
                nonlocal conn_handle
                cc_view = hci_packets.LeConnectionCompleteView(
                    hci_packets.LeMetaEventView(
                        hci_packets.EventPacketView(bt_packets.PacketViewLittleEndian(list(packet_bytes)))))
                conn_handle = cc_view.GetConnectionHandle()
                return True
            return False

        assertThat(self.cert_hal.get_hci_event_stream()).emits(payload_handle)
        cert_handle = conn_handle
        conn_handle = 0xfff
        assertThat(self.dut_hal.get_hci_event_stream()).emits(payload_handle)
        dut_handle = conn_handle

        # Send ACL Data
        self.dut_hal.send_acl(dut_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                              hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'Just SomeAclData'))
        self.cert_hal.send_acl(cert_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                               hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'Just SomeMoreAclData'))

        assertThat(self.cert_hal.get_acl_stream()).emits(lambda packet: b'SomeAclData' in packet.payload)
        assertThat(self.dut_hal.get_acl_stream()).emits(lambda packet: b'SomeMoreAclData' in packet.payload)

    def test_le_connect_list_connection_cert_advertises(self):
        # DUT Connects
        self.dut_hal.send_hci_command(hci_packets.LeSetRandomAddressBuilder('0D:05:04:03:02:01'))
        self.dut_hal.send_hci_command(
            hci_packets.LeAddDeviceToConnectListBuilder(hci_packets.ConnectListAddressType.RANDOM, '0C:05:04:03:02:01'))
        phy_scan_params = hci_packets.LeCreateConnPhyScanParameters()
        phy_scan_params.scan_interval = 0x60
        phy_scan_params.scan_window = 0x30
        phy_scan_params.conn_interval_min = 0x18
        phy_scan_params.conn_interval_max = 0x28
        phy_scan_params.conn_latency = 0
        phy_scan_params.supervision_timeout = 0x1f4
        phy_scan_params.min_ce_length = 0
        phy_scan_params.max_ce_length = 0
        self.dut_hal.send_hci_command(
            hci_packets.LeExtendedCreateConnectionBuilder(
                hci_packets.InitiatorFilterPolicy.USE_CONNECT_LIST, hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, 'BA:D5:A4:A3:A2:A1', 1, [phy_scan_params]))

        # CERT Advertises
        advertising_handle = 1
        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingLegacyParametersBuilder(
                advertising_handle,
                hci_packets.LegacyAdvertisingProperties.ADV_IND,
                512,
                768,
                7,
                hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                'A6:A5:A4:A3:A2:A1',
                hci_packets.AdvertisingFilterPolicy.ALL_DEVICES,
                0x7F,
                0,  # SID
                hci_packets.Enable.DISABLED  # Scan request notification
            ))

        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingRandomAddressBuilder(advertising_handle, '0C:05:04:03:02:01'))

        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_A_Cert'))

        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingDataBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_name]))
        enabled_set = hci_packets.EnabledSet()
        enabled_set.advertising_handle = 1
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.ENABLED, [enabled_set]))

        # LeConnectionComplete
        assertThat(self.cert_hal.get_hci_event_stream()).emits(
            lambda packet: b'\x3e\x13\x01\x00' in packet.payload, timeout=timedelta(seconds=20))
        assertThat(self.dut_hal.get_hci_event_stream()).emits(
            lambda packet: b'\x3e\x13\x01\x00' in packet.payload, timeout=timedelta(seconds=20))
