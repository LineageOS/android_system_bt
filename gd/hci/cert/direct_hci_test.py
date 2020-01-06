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
from hal import facade_pb2 as hal_facade
from hci.facade import facade_pb2 as hci_facade
from bluetooth_packets_python3 import hci_packets
import bluetooth_packets_python3 as bt_packets


class DirectHciTest(GdFacadeOnlyBaseTestClass):

    def setup_test(self):
        self.cert_device = self.gd_devices[0]
        self.device_under_test = self.gd_devices[1]

        self.device_under_test.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    'HCI'),))
        self.cert_device.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    'HAL'),))

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

        self.cert_device.hal.SendHciResetCommand(empty_proto.Empty())

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice.StopStackRequest())
        self.cert_device.rootservice.StopStack(
            facade_rootservice.StopStackRequest())

    def register_for_event(self, event_code):
        msg = hci_facade.EventCodeMsg(code=int(event_code))
        self.device_under_test.hci.RegisterEventHandler(msg)

    def register_for_le_event(self, event_code):
        msg = hci_facade.LeSubeventCodeMsg(code=int(event_code))
        self.device_under_test.hci.RegisterLeEventHandler(msg)

    def enqueue_hci_command(self, command, expect_complete):
        cmd_bytes = bytes(command.Serialize())
        cmd = hci_facade.CommandMsg(command=cmd_bytes)
        if (expect_complete):
            self.device_under_test.hci.EnqueueCommandWithComplete(cmd)
        else:
            self.device_under_test.hci.EnqueueCommandWithStatus(cmd)

    def send_hal_hci_command(self, command):
        self.cert_device.hal.SendHciCommand(
            hal_facade.HciCommandPacket(payload=bytes(command.Serialize())))

    def enqueue_acl_data(self, handle, pb_flag, b_flag, acl):
        acl_msg = hci_facade.AclMsg(
            handle=int(handle),
            packet_boundary_flag=int(pb_flag),
            broadcast_flag=int(b_flag),
            data=acl)
        self.device_under_test.hci.SendAclData(acl_msg)

    def send_hal_acl_data(self, handle, pb_flag, b_flag, acl):
        lower = handle & 0xff
        upper = (handle >> 8) & 0xf
        upper = upper | int(pb_flag) & 0x3
        upper = upper | ((int(b_flag) & 0x3) << 2)
        lower_length = len(acl) & 0xff
        upper_length = (len(acl) & 0xff00) >> 8
        concatenated = bytes([lower, upper, lower_length, upper_length] +
                             list(acl))
        self.cert_device.hal.SendHciAcl(
            hal_facade.HciAclPacket(payload=concatenated))

    def test_local_hci_cmd_and_event(self):
        # Loopback mode responds with ACL and SCO connection complete
        self.register_for_event(hci_packets.EventCode.CONNECTION_COMPLETE)
        self.register_for_event(hci_packets.EventCode.LOOPBACK_COMMAND)
        with EventCallbackStream(
                self.device_under_test.hci.FetchEvents(
                    empty_proto.Empty())) as hci_event_stream:

            self.enqueue_hci_command(
                hci_packets.WriteLoopbackModeBuilder(
                    hci_packets.LoopbackMode.ENABLE_LOCAL), True)

            cmd2loop = hci_packets.ReadLocalNameBuilder()
            self.enqueue_hci_command(cmd2loop, True)

            looped_bytes = bytes(cmd2loop.Serialize())
            hci_event_asserts = EventAsserts(hci_event_stream)
            hci_event_asserts.assert_event_occurs(
                lambda packet: looped_bytes in packet.event)

    def test_inquiry_from_dut(self):
        self.register_for_event(hci_packets.EventCode.INQUIRY_RESULT)
        with EventCallbackStream(
                self.device_under_test.hci.FetchEvents(
                    empty_proto.Empty())) as hci_event_stream:
            self.send_hal_hci_command(
                hci_packets.WriteScanEnableBuilder(
                    hci_packets.ScanEnable.INQUIRY_AND_PAGE_SCAN))
            lap = hci_packets.Lap()
            lap.lap = 0x33
            self.enqueue_hci_command(
                hci_packets.InquiryBuilder(lap, 0x30, 0xff), False)
            hci_event_asserts = EventAsserts(hci_event_stream)
            hci_event_asserts.assert_event_occurs(
                lambda packet: b'\x02\x0f' in packet.event
                # Expecting an HCI Event (code 0x02, length 0x0f)
            )

    def test_le_ad_scan_cert_advertises(self):
        self.register_for_le_event(hci_packets.SubeventCode.ADVERTISING_REPORT)
        with EventCallbackStream(
                self.device_under_test.hci.FetchLeSubevents(
                    empty_proto.Empty())) as hci_le_event_stream:

            # DUT Scans
            self.enqueue_hci_command(
                hci_packets.LeSetRandomAddressBuilder('0D:05:04:03:02:01'),
                True)
            self.enqueue_hci_command(
                hci_packets.LeSetScanParametersBuilder(
                    hci_packets.LeScanType.ACTIVE, 40, 20,
                    hci_packets.AddressType.RANDOM_DEVICE_ADDRESS,
                    hci_packets.LeSetScanningFilterPolicy.ACCEPT_ALL), True)
            self.enqueue_hci_command(
                hci_packets.LeSetScanEnableBuilder(
                    hci_packets.Enable.ENABLED,
                    hci_packets.Enable.DISABLED),  # duplicate filtering
                True)

            # CERT Advertises
            self.send_hal_hci_command(
                hci_packets.LeSetRandomAddressBuilder('0C:05:04:03:02:01'))
            self.send_hal_hci_command(
                hci_packets.LeSetAdvertisingParametersBuilder(
                    512, 768, hci_packets.AdvertisingEventType.ADV_IND,
                    hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, hci_packets.
                    PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                    'A6:A5:A4:A3:A2:A1', 7,
                    hci_packets.AdvertisingFilterPolicy.ALL_DEVICES))

            gap_name = hci_packets.GapData()
            gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
            gap_name.data = list(bytes(b'Im_A_Cert!'))  # TODO: Fix and remove !
            gap_data = list([gap_name])

            self.send_hal_hci_command(
                hci_packets.LeSetAdvertisingDataBuilder(gap_data))
            self.send_hal_hci_command(
                hci_packets.LeSetAdvertisingEnableBuilder(
                    hci_packets.Enable.ENABLED))

            hci_event_asserts = EventAsserts(hci_le_event_stream)
            hci_event_asserts.assert_event_occurs(
                lambda packet: b'Im_A_Cert' in packet.event)

            self.send_hal_hci_command(
                hci_packets.LeSetAdvertisingEnableBuilder(
                    hci_packets.Enable.DISABLED))
            self.enqueue_hci_command(
                hci_packets.LeSetScanEnableBuilder(hci_packets.Enable.DISABLED,
                                                   hci_packets.Enable.DISABLED),
                True)

    def test_le_connection_dut_advertises(self):
        self.register_for_le_event(hci_packets.SubeventCode.CONNECTION_COMPLETE)
        with EventCallbackStream(self.device_under_test.hci.FetchLeSubevents(empty_proto.Empty())) as le_event_stream, \
            EventCallbackStream(self.device_under_test.hci.FetchAclPackets(empty_proto.Empty())) as acl_data_stream, \
            EventCallbackStream(self.cert_device.hal.FetchHciEvent(empty_proto.Empty())) as cert_hci_event_stream, \
            EventCallbackStream(self.cert_device.hal.FetchHciAcl(empty_proto.Empty())) as cert_acl_data_stream:

            self.send_hal_hci_command(
                hci_packets.LeSetRandomAddressBuilder('0C:05:04:03:02:01'))

            self.send_hal_hci_command(
                hci_packets.LeCreateConnectionBuilder(
                    0x111, 0x222,
                    hci_packets.InitiatorFilterPolicy.USE_PEER_ADDRESS,
                    hci_packets.AddressType.RANDOM_DEVICE_ADDRESS,
                    '0D:05:04:03:02:01',
                    hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS, 0x06,
                    0xC70, 0x40, 0x703, 0x01, 0x02))

            # DUT Advertises
            self.enqueue_hci_command(
                hci_packets.LeSetRandomAddressBuilder('0D:05:04:03:02:01'),
                True)
            self.enqueue_hci_command(
                hci_packets.LeSetAdvertisingParametersBuilder(
                    512, 768, hci_packets.AdvertisingEventType.ADV_IND,
                    hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, hci_packets.
                    PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                    'A6:A5:A4:A3:A2:A1', 7,
                    hci_packets.AdvertisingFilterPolicy.ALL_DEVICES), True)

            gap_name = hci_packets.GapData()
            gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
            gap_name.data = list(
                bytes(b'Im_The_DUT!'))  # TODO: Fix and remove !
            gap_data = list([gap_name])

            self.enqueue_hci_command(
                hci_packets.LeSetAdvertisingDataBuilder(gap_data), True)
            self.enqueue_hci_command(
                hci_packets.LeSetAdvertisingEnableBuilder(
                    hci_packets.Enable.ENABLED), True)

            conn_handle = 0xfff

            def event_handle(packet):
                packet_bytes = packet.event
                if b'\x3e\x13\x01\x00' in packet_bytes:
                    nonlocal conn_handle
                    cc_view = hci_packets.LeConnectionCompleteView(
                        hci_packets.LeMetaEventView(
                            hci_packets.EventPacketView(
                                bt_packets.PacketViewLittleEndian(
                                    list(packet_bytes)))))
                    conn_handle = cc_view.GetConnectionHandle()
                    return True
                return False

            def payload_handle(packet):
                packet_bytes = packet.payload
                if b'\x3e\x13\x01\x00' in packet_bytes:
                    nonlocal conn_handle
                    cc_view = hci_packets.LeConnectionCompleteView(
                        hci_packets.LeMetaEventView(
                            hci_packets.EventPacketView(
                                bt_packets.PacketViewLittleEndian(
                                    list(packet_bytes)))))
                    conn_handle = cc_view.GetConnectionHandle()
                    return True
                return False

            le_event_asserts = EventAsserts(le_event_stream)
            cert_hci_event_asserts = EventAsserts(cert_hci_event_stream)

            cert_hci_event_asserts.assert_event_occurs(payload_handle)
            cert_handle = conn_handle
            conn_handle = 0xfff
            le_event_asserts.assert_event_occurs(event_handle)
            dut_handle = conn_handle
            if dut_handle == 0xfff:
                logging.warning("Failed to get the DUT handle")
                return False
            if cert_handle == 0xfff:
                logging.warning("Failed to get the CERT handle")
                return False

            # Send ACL Data
            self.enqueue_acl_data(
                dut_handle, hci_packets.PacketBoundaryFlag.
                FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                hci_packets.BroadcastFlag.POINT_TO_POINT,
                bytes(b'This is just SomeAclData'))
            self.send_hal_acl_data(
                cert_handle, hci_packets.PacketBoundaryFlag.
                FIRST_NON_AUTOMATICALLY_FLUSHABLE,
                hci_packets.BroadcastFlag.POINT_TO_POINT,
                bytes(b'This is just SomeMoreAclData'))

            acl_data_asserts = EventAsserts(acl_data_stream)
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_asserts.assert_event_occurs(
                lambda packet: logging.debug(packet.payload) or b'SomeAclData' in packet.payload
            )
            acl_data_asserts.assert_event_occurs(
                lambda packet: logging.debug(packet.data) or b'SomeMoreAclData' in packet.data
            )

    def test_le_white_list_connection_cert_advertises(self):
        self.register_for_le_event(hci_packets.SubeventCode.CONNECTION_COMPLETE)
        with EventCallbackStream(self.device_under_test.hci.FetchLeSubevents(empty_proto.Empty())) as le_event_stream, \
                EventCallbackStream(self.cert_device.hal.FetchHciEvent(empty_proto.Empty())) as cert_hci_event_stream:
            le_event_asserts = EventAsserts(le_event_stream)
            cert_hci_event_asserts = EventAsserts(cert_hci_event_stream)

            self.enqueue_hci_command(
                hci_packets.LeSetRandomAddressBuilder('0D:05:04:03:02:01'),
                True)
            self.enqueue_hci_command(
                hci_packets.LeAddDeviceToWhiteListBuilder(
                    hci_packets.WhiteListAddressType.RANDOM,
                    '0C:05:04:03:02:01'), True)
            self.enqueue_hci_command(
                hci_packets.LeCreateConnectionBuilder(
                    0x111, 0x222,
                    hci_packets.InitiatorFilterPolicy.USE_WHITE_LIST,
                    hci_packets.AddressType.RANDOM_DEVICE_ADDRESS,
                    'BA:D5:A4:A3:A2:A1',
                    hci_packets.OwnAddressType.RANDOM_DEVICE_ADDRESS, 0x06,
                    0xC70, 0x40, 0x703, 0x01, 0x02), False)

            # CERT Advertises
            self.send_hal_hci_command(
                hci_packets.LeSetRandomAddressBuilder('0C:05:04:03:02:01'))
            self.send_hal_hci_command(
                hci_packets.LeSetAdvertisingParametersBuilder(
                    512, 768, hci_packets.AdvertisingEventType.ADV_IND,
                    hci_packets.AddressType.RANDOM_DEVICE_ADDRESS, hci_packets.
                    PeerAddressType.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS,
                    'A6:A5:A4:A3:A2:A1', 7,
                    hci_packets.AdvertisingFilterPolicy.ALL_DEVICES))

            gap_name = hci_packets.GapData()
            gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
            gap_name.data = list(bytes(b'Im_A_Cert!'))  # TODO: Fix and remove !
            gap_data = list([gap_name])

            self.send_hal_hci_command(
                hci_packets.LeSetAdvertisingDataBuilder(gap_data))
            self.send_hal_hci_command(
                hci_packets.LeSetAdvertisingEnableBuilder(
                    hci_packets.Enable.ENABLED))

            # LeConnectionComplete
            cert_hci_event_asserts.assert_event_occurs(
                lambda packet: b'\x3e\x13\x01\x00' in packet.payload)
            le_event_asserts.assert_event_occurs(
                lambda packet: b'\x3e\x13\x01\x00' in packet.event)
