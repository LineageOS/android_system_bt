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
import logging

from cert.captures import HalCaptures, HciCaptures
from cert.gd_base_test import GdBaseTestClass
from cert.matchers import HciMatchers
from cert.py_hal import PyHal
from cert.py_hci import PyHci
from cert.truth import assertThat
from hci.facade import facade_pb2 as hci_facade
from bluetooth_packets_python3 import hci_packets


class DirectHciTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='HCI', cert_module='HAL')

    def setup_test(self):
        super().setup_test()
        self.dut_hci = PyHci(self.dut, acl_streaming=True)
        self.cert_hal = PyHal(self.cert)
        self.cert_hal.send_hci_command(hci_packets.ResetBuilder())

    def teardown_test(self):
        self.dut_hci.close()
        self.cert_hal.close()
        super().teardown_test()

    def enqueue_acl_data(self, handle, pb_flag, b_flag, acl):
        acl_msg = hci_facade.AclPacket(
            handle=int(handle), packet_boundary_flag=int(pb_flag), broadcast_flag=int(b_flag), data=acl)
        self.dut.hci.SendAcl(acl_msg)

    def send_hal_acl_data(self, handle, pb_flag, b_flag, acl):
        lower = handle & 0xff
        upper = (handle >> 8) & 0xf
        upper = upper | int(pb_flag) & 0x3
        upper = upper | ((int(b_flag) & 0x3) << 2)
        lower_length = len(acl) & 0xff
        upper_length = (len(acl) & 0xff00) >> 8
        concatenated = bytes([lower, upper, lower_length, upper_length] + list(acl))
        self.cert_hal.send_acl(concatenated)

    def test_local_hci_cmd_and_event(self):
        # Loopback mode responds with ACL and SCO connection complete
        self.dut_hci.register_for_events(hci_packets.EventCode.LOOPBACK_COMMAND)

        self.dut_hci.send_command_with_complete(
            hci_packets.WriteLoopbackModeBuilder(hci_packets.LoopbackMode.ENABLE_LOCAL))

        cmd2loop = hci_packets.ReadLocalNameBuilder()
        self.dut_hci.send_command_with_complete(cmd2loop)

        looped_bytes = bytes(cmd2loop.Serialize())
        assertThat(self.dut_hci.get_event_stream()).emits(lambda packet: looped_bytes in packet.payload)

    def test_inquiry_from_dut(self):
        self.dut_hci.register_for_events(hci_packets.EventCode.INQUIRY_RESULT)

        self.cert_hal.send_hci_command(hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))
        lap = hci_packets.Lap()
        lap.lap = 0x33
        self.dut_hci.send_command_with_status(hci_packets.InquiryBuilder(lap, 0x30, 0xff))
        assertThat(self.dut_hci.get_event_stream()).emits(
            HciMatchers.EventWithCode(hci_packets.EventCode.INQUIRY_RESULT))

    def test_le_ad_scan_cert_advertises(self):
        self.dut_hci.register_for_le_events(hci_packets.SubeventCode.EXTENDED_ADVERTISING_REPORT)
        self.dut_hci.register_for_le_events(hci_packets.SubeventCode.ADVERTISING_REPORT)

        # DUT Scans
        self.dut_hci.send_command_with_complete(hci_packets.LeSetRandomAddressBuilder('0D:05:04:03:02:01'))
        phy_scan_params = hci_packets.PhyScanParameters()
        phy_scan_params.le_scan_interval = 6553
        phy_scan_params.le_scan_window = 6553
        phy_scan_params.le_scan_type = hci_packets.LeScanType.ACTIVE

        self.dut_hci.send_command_with_complete(
            hci_packets.LeSetExtendedScanParametersBuilder(hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                                                           hci_packets.LeScanningFilterPolicy.ACCEPT_ALL, 1,
                                                           [phy_scan_params]))
        self.dut_hci.send_command_with_complete(
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
                0xF7,
                1,  # SID
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

        gap_short_name = hci_packets.GapData()
        gap_short_name.data_type = hci_packets.GapDataType.SHORTENED_LOCAL_NAME
        gap_short_name.data = list(bytes(b'Im_A_C'))

        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingScanResponseBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_short_name]))

        enabled_set = hci_packets.EnabledSet()
        enabled_set.advertising_handle = 0
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.ENABLED, [enabled_set]))

        assertThat(self.dut_hci.get_le_event_stream()).emits(lambda packet: b'Im_A_Cert' in packet.payload)

        self.cert_hal.send_hci_command(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.DISABLED, [enabled_set]))
        self.dut_hci.send_command_with_complete(
            hci_packets.LeSetExtendedScanEnableBuilder(hci_packets.Enable.DISABLED,
                                                       hci_packets.FilterDuplicates.DISABLED, 0, 0))

    def _verify_le_connection_complete(self):
        cert_conn_complete_capture = HalCaptures.LeConnectionCompleteCapture()
        assertThat(self.cert_hal.get_hci_event_stream()).emits(cert_conn_complete_capture)
        cert_handle = cert_conn_complete_capture.get().GetConnectionHandle()

        dut_conn_complete_capture = HciCaptures.LeConnectionCompleteCapture()
        assertThat(self.dut_hci.get_le_event_stream()).emits(dut_conn_complete_capture)
        dut_handle = dut_conn_complete_capture.get().GetConnectionHandle()

        return (dut_handle, cert_handle)

    @staticmethod
    def _create_phy_scan_params():
        phy_scan_params = hci_packets.LeCreateConnPhyScanParameters()
        phy_scan_params.scan_interval = 0x60
        phy_scan_params.scan_window = 0x30
        phy_scan_params.conn_interval_min = 0x18
        phy_scan_params.conn_interval_max = 0x28
        phy_scan_params.conn_latency = 0
        phy_scan_params.supervision_timeout = 0x1f4
        phy_scan_params.min_ce_length = 0
        phy_scan_params.max_ce_length = 0
        return phy_scan_params

    def test_le_connection_dut_advertises(self):
        self.dut_hci.register_for_le_events(hci_packets.SubeventCode.CONNECTION_COMPLETE)
        self.dut_hci.register_for_le_events(hci_packets.SubeventCode.ADVERTISING_SET_TERMINATED)
        self.dut_hci.register_for_le_events(hci_packets.SubeventCode.ENHANCED_CONNECTION_COMPLETE)
        # Cert Connects
        self.cert_hal.send_hci_command(hci_packets.LeSetRandomAddressBuilder('0C:05:04:03:02:01'))
        phy_scan_params = DirectHciTest._create_phy_scan_params()
        self.cert_hal.send_hci_command(
            hci_packets.LeExtendedCreateConnectionBuilder(
                hci_packets.InitiatorFilterPolicy.USE_PEER_ADDRESS, hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS,
                hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, '0D:05:04:03:02:01', 1, [phy_scan_params]))

        # DUT Advertises
        advertising_handle = 0
        self.dut_hci.send_command_with_complete(
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

        self.dut_hci.send_command_with_complete(
            hci_packets.LeSetExtendedAdvertisingRandomAddressBuilder(advertising_handle, '0D:05:04:03:02:01'))

        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(b'Im_The_DUT'))

        self.dut_hci.send_command_with_complete(
            hci_packets.LeSetExtendedAdvertisingDataBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_name]))

        gap_short_name = hci_packets.GapData()
        gap_short_name.data_type = hci_packets.GapDataType.SHORTENED_LOCAL_NAME
        gap_short_name.data = list(bytes(b'Im_The_D'))

        self.dut_hci.send_command_with_complete(
            hci_packets.LeSetExtendedAdvertisingScanResponseBuilder(
                advertising_handle, hci_packets.Operation.COMPLETE_ADVERTISEMENT,
                hci_packets.FragmentPreference.CONTROLLER_SHOULD_NOT, [gap_short_name]))

        enabled_set = hci_packets.EnabledSet()
        enabled_set.advertising_handle = advertising_handle
        enabled_set.duration = 0
        enabled_set.max_extended_advertising_events = 0
        self.dut_hci.send_command_with_complete(
            hci_packets.LeSetExtendedAdvertisingEnableBuilder(hci_packets.Enable.ENABLED, [enabled_set]))

        # Check for success of Enable
        assertThat(self.dut_hci.get_event_stream()).emits(
            HciMatchers.CommandComplete(hci_packets.OpCode.LE_SET_EXTENDED_ADVERTISING_ENABLE))

        (dut_handle, cert_handle) = self._verify_le_connection_complete()

        # Send ACL Data
        self.enqueue_acl_data(dut_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                              hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'Just SomeAclData'))
        self.send_hal_acl_data(cert_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                               hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'Just SomeMoreAclData'))

        assertThat(self.cert_hal.get_acl_stream()).emits(
            lambda packet: logging.debug(packet.payload) or b'SomeAclData' in packet.payload)
        assertThat(self.dut_hci.get_raw_acl_stream()).emits(
            lambda packet: logging.debug(packet.data) or b'SomeMoreAclData' in packet.data)

    def test_le_connect_list_connection_cert_advertises(self):
        self.dut_hci.register_for_le_events(hci_packets.SubeventCode.CONNECTION_COMPLETE)
        self.dut_hci.register_for_le_events(hci_packets.SubeventCode.ENHANCED_CONNECTION_COMPLETE)
        # DUT Connects
        self.dut_hci.send_command_with_complete(hci_packets.LeSetRandomAddressBuilder('0D:05:04:03:02:01'))
        self.dut_hci.send_command_with_complete(
            hci_packets.LeAddDeviceToConnectListBuilder(hci_packets.ConnectListAddressType.RANDOM, '0C:05:04:03:02:01'))
        phy_scan_params = DirectHciTest._create_phy_scan_params()
        self.dut_hci.send_command_with_status(
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
        self._verify_le_connection_complete()

    def _verify_connection_complete(self):
        cert_connection_complete_capture = HalCaptures.ConnectionCompleteCapture()
        assertThat(self.cert_hal.get_hci_event_stream()).emits(cert_connection_complete_capture)
        cert_handle = cert_connection_complete_capture.get().GetConnectionHandle()

        dut_connection_complete_capture = HciCaptures.ConnectionCompleteCapture()
        assertThat(self.dut_hci.get_event_stream()).emits(dut_connection_complete_capture)
        dut_handle = dut_connection_complete_capture.get().GetConnectionHandle()

        return (dut_handle, cert_handle)

    def test_connection_dut_connects(self):
        self.dut_hci.send_command_with_complete(hci_packets.WritePageTimeoutBuilder(0x4000))

        # CERT Enables scans and gets its address
        self.cert_hal.send_hci_command(hci_packets.ReadBdAddrBuilder())

        cert_read_bd_addr_capture = HalCaptures.ReadBdAddrCompleteCapture()
        assertThat(self.cert_hal.get_hci_event_stream()).emits(cert_read_bd_addr_capture)
        address = cert_read_bd_addr_capture.get().GetBdAddr()

        self.cert_hal.send_hci_command(hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))

        # DUT Connects
        self.dut_hci.send_command_with_status(
            hci_packets.CreateConnectionBuilder(
                address,
                0xcc18,  # Packet Type
                hci_packets.PageScanRepetitionMode.R0,
                0,
                hci_packets.ClockOffsetValid.INVALID,
                hci_packets.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH))

        # Cert Accepts
        connect_request_capture = HalCaptures.ConnectionRequestCapture()
        assertThat(self.cert_hal.get_hci_event_stream()).emits(connect_request_capture, timeout=timedelta(seconds=20))
        connection_request = connect_request_capture.get()
        self.cert_hal.send_hci_command(
            hci_packets.AcceptConnectionRequestBuilder(connection_request.GetBdAddr(),
                                                       hci_packets.AcceptConnectionRequestRole.REMAIN_PERIPHERAL))

        (dut_handle, cert_handle) = self._verify_connection_complete()

        # Send ACL Data
        self.enqueue_acl_data(dut_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                              hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'Just SomeAclData'))
        self.send_hal_acl_data(cert_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                               hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'Just SomeMoreAclData'))

        assertThat(self.cert_hal.get_acl_stream()).emits(lambda packet: b'SomeAclData' in packet.payload)
        assertThat(self.dut_hci.get_raw_acl_stream()).emits(lambda packet: b'SomeMoreAclData' in packet.data)

    def test_connection_cert_connects(self):
        self.cert_hal.send_hci_command(hci_packets.WritePageTimeoutBuilder(0x4000))

        # DUT Enables scans and gets its address
        self.dut_hci.send_command_with_complete(
            hci_packets.WriteScanEnableBuilder(hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))
        self.dut_hci.send_command_with_complete(hci_packets.ReadBdAddrBuilder())

        read_bd_addr_capture = HciCaptures.ReadBdAddrCompleteCapture()
        assertThat(self.dut_hci.get_event_stream()).emits(read_bd_addr_capture)
        address = read_bd_addr_capture.get().GetBdAddr()

        # Cert Connects
        self.cert_hal.send_hci_command(
            hci_packets.CreateConnectionBuilder(
                address,
                0xcc18,  # Packet Type
                hci_packets.PageScanRepetitionMode.R0,
                0,
                hci_packets.ClockOffsetValid.INVALID,
                hci_packets.CreateConnectionRoleSwitch.ALLOW_ROLE_SWITCH))

        # DUT Accepts
        connection_request_capture = HciCaptures.ConnectionRequestCapture()
        assertThat(self.dut_hci.get_event_stream()).emits(connection_request_capture, timeout=timedelta(seconds=20))
        connection_request = connection_request_capture.get()
        self.dut_hci.send_command_with_status(
            hci_packets.AcceptConnectionRequestBuilder(connection_request.GetBdAddr(),
                                                       hci_packets.AcceptConnectionRequestRole.REMAIN_PERIPHERAL))

        (dut_handle, cert_handle) = self._verify_connection_complete()

        # Send ACL Data
        self.enqueue_acl_data(dut_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                              hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'This is just SomeAclData'))
        self.send_hal_acl_data(cert_handle, hci_packets.PacketBoundaryFlag.FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                               hci_packets.BroadcastFlag.POINT_TO_POINT, bytes(b'This is just SomeMoreAclData'))

        assertThat(self.cert_hal.get_acl_stream()).emits(lambda packet: b'SomeAclData' in packet.payload)
        assertThat(self.dut_hci.get_raw_acl_stream()).emits(lambda packet: b'SomeMoreAclData' in packet.data)
