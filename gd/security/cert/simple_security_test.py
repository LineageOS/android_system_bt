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
import os
import sys
import logging

from cert.gd_base_test import GdBaseTestClass
from cert.event_stream import EventStream
from google.protobuf import empty_pb2 as empty_proto
from facade import common_pb2 as common
from facade import rootservice_pb2 as facade_rootservice_pb2
from hci.facade import facade_pb2 as hci_facade
from hci.facade import acl_manager_facade_pb2 as acl_manager_facade
from hci.facade import controller_facade_pb2 as controller_facade
from l2cap.classic import facade_pb2 as l2cap_facade
from neighbor.facade import facade_pb2 as neighbor_facade
from security import facade_pb2 as security_facade
from bluetooth_packets_python3 import hci_packets
import bluetooth_packets_python3 as bt_packets


class SimpleSecurityTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='SECURITY', cert_module='L2CAP')

    def setup_test(self):
        super().setup_test()

        self.dut.address = self.dut.controller_read_only_property.ReadLocalAddress(
            empty_proto.Empty()).address
        self.cert.address = self.cert.controller_read_only_property.ReadLocalAddress(
            empty_proto.Empty()).address

        self.dut.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))
        self.cert.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))

        self.dut_address = common.BluetoothAddress(address=self.dut.address)
        self.cert_address = common.BluetoothAddress(address=self.cert.address)

        self.dut_address_with_type = common.BluetoothAddressWithType()
        self.dut_address_with_type.address.CopyFrom(self.dut_address)
        self.dut_address_with_type.type = common.BluetoothPeerAddressTypeEnum.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS

        self.cert_address_with_type = common.BluetoothAddressWithType()
        self.cert_address_with_type.address.CopyFrom(self.cert_address)
        self.cert_address_with_type.type = common.BluetoothPeerAddressTypeEnum.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS

        self.dut.wait_channel_ready()
        self.cert.wait_channel_ready()

        self.cert_name = b'ImTheCert'
        self.cert.hci_controller.WriteLocalName(
            controller_facade.NameMsg(name=self.cert_name))
        self.dut_name = b'ImTheDUT'
        self.dut.hci_controller.WriteLocalName(
            controller_facade.NameMsg(name=self.dut_name))

    def tmp_register_for_event(self, event_code):
        msg = hci_facade.EventCodeMsg(code=int(event_code))
        self.dut.hci.RegisterEventHandler(msg)

    def tmp_enqueue_hci_command(self, command, expect_complete):
        cmd_bytes = bytes(command.Serialize())
        cmd = hci_facade.CommandMsg(command=cmd_bytes)
        if (expect_complete):
            self.dut.hci.EnqueueCommandWithComplete(cmd)
        else:
            self.dut.hci.EnqueueCommandWithStatus(cmd)

    def register_for_event(self, event_code):
        msg = hci_facade.EventCodeMsg(code=int(event_code))
        self.cert.hci.RegisterEventHandler(msg)

    def enqueue_hci_command(self, command, expect_complete):
        cmd_bytes = bytes(command.Serialize())
        cmd = hci_facade.CommandMsg(command=cmd_bytes)
        if (expect_complete):
            self.cert.hci.EnqueueCommandWithComplete(cmd)
        else:
            self.cert.hci.EnqueueCommandWithStatus(cmd)

    def enqueue_acl_data(self, handle, pb_flag, b_flag, acl):
        acl_msg = hci_facade.AclMsg(
            handle=int(handle),
            packet_boundary_flag=int(pb_flag),
            broadcast_flag=int(b_flag),
            data=acl)
        self.cert.hci.SendAclData(acl_msg)

    def pair_justworks(self, cert_iocap_reply, expected_ui_event):
        # Cert event registration
        self.register_for_event(hci_packets.EventCode.LINK_KEY_REQUEST)
        self.register_for_event(hci_packets.EventCode.IO_CAPABILITY_REQUEST)
        self.register_for_event(hci_packets.EventCode.IO_CAPABILITY_RESPONSE)
        self.register_for_event(hci_packets.EventCode.USER_PASSKEY_NOTIFICATION)
        self.register_for_event(hci_packets.EventCode.USER_CONFIRMATION_REQUEST)
        self.register_for_event(
            hci_packets.EventCode.REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION)
        self.register_for_event(hci_packets.EventCode.LINK_KEY_NOTIFICATION)
        self.register_for_event(hci_packets.EventCode.SIMPLE_PAIRING_COMPLETE)
        with EventStream(self.dut.security.FetchUiEvents(empty_proto.Empty())) as dut_ui_stream, \
            EventStream(self.dut.security.FetchBondEvents(empty_proto.Empty())) as dut_bond_stream, \
            EventStream(self.dut.neighbor.GetRemoteNameEvents(empty_proto.Empty())) as dut_name_stream, \
            EventStream(self.cert.hci.FetchEvents(empty_proto.Empty())) as cert_hci_event_stream:

            dut_address = self.dut.hci_controller.GetMacAddress(
                empty_proto.Empty()).address
            cert_address = self.cert.hci_controller.GetMacAddress(
                empty_proto.Empty()).address

            # Enable Simple Secure Pairing
            self.enqueue_hci_command(
                hci_packets.WriteSimplePairingModeBuilder(
                    hci_packets.Enable.ENABLED), True)

            cert_hci_event_stream.assert_event_occurs(
                lambda msg: b'\x0e\x04\x01\x56\x0c' in msg.event)

            # Get the name
            self.dut.neighbor.ReadRemoteName(
                neighbor_facade.RemoteNameRequestMsg(
                    address=cert_address,
                    page_scan_repetition_mode=1,
                    clock_offset=0x6855))

            dut_name_stream.assert_event_occurs(
                lambda msg: self.cert_name in msg.name)

            self.dut.security.CreateBond(
                common.BluetoothAddressWithType(
                    address=common.BluetoothAddress(address=cert_address),
                    type=common.BluetoothAddressTypeEnum.PUBLIC_DEVICE_ADDRESS))

            cert_hci_event_stream.assert_event_occurs(
                lambda event: logging.debug(event.event) or hci_packets.EventCode.IO_CAPABILITY_REQUEST in event.event
            )

            self.enqueue_hci_command(cert_iocap_reply, True)

            cert_hci_event_stream.assert_event_occurs(
                lambda event: logging.debug(event.event) or hci_packets.EventCode.USER_CONFIRMATION_REQUEST in event.event
            )
            self.enqueue_hci_command(
                hci_packets.UserConfirmationRequestReplyBuilder(
                    dut_address.decode('utf8')), True)

            logging.info("Waiting for UI event")
            ui_id = -1

            def get_unique_id(event):
                if (event.message_type == expected_ui_event):
                    nonlocal ui_id
                    ui_id = event.unique_id
                    return True
                return False

            dut_ui_stream.assert_event_occurs(get_unique_id)

            logging.info("Sending UI response")
            self.dut.security.SendUiCallback(
                security_facade.UiCallbackMsg(
                    message_type=security_facade.UiCallbackType.YES_NO,
                    boolean=True,
                    unique_id=ui_id,
                    address=common.BluetoothAddressWithType(
                        address=common.BluetoothAddress(address=cert_address),
                        type=common.BluetoothAddressTypeEnum.
                        PUBLIC_DEVICE_ADDRESS)))

            # TODO: Figure out why this isn't happening anymore, bond event changes were recently introduced
            # dut_bond_stream.assert_event_occurs(
            #     lambda bond_event: bond_event.message_type == security_facade.BondMsgType.DEVICE_BONDED
            # )

    def test_display_only(self):
        dut_address = self.dut.hci_controller.GetMacAddress(
            empty_proto.Empty()).address
        self.pair_justworks(
            hci_packets.IoCapabilityRequestReplyBuilder(
                dut_address.decode('utf8'),
                hci_packets.IoCapability.DISPLAY_ONLY,
                hci_packets.OobDataPresent.NOT_PRESENT, hci_packets.
                AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION),
            security_facade.UiMsgType.DISPLAY_YES_NO_WITH_VALUE)

    def test_no_input_no_output(self):
        dut_address = self.dut.hci_controller.GetMacAddress(
            empty_proto.Empty()).address
        self.pair_justworks(
            hci_packets.IoCapabilityRequestReplyBuilder(
                dut_address.decode('utf8'),
                hci_packets.IoCapability.NO_INPUT_NO_OUTPUT,
                hci_packets.OobDataPresent.NOT_PRESENT, hci_packets.
                AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION),
            security_facade.UiMsgType.DISPLAY_YES_NO)

    def test_display_yes_no(self):
        dut_address = self.dut.hci_controller.GetMacAddress(
            empty_proto.Empty()).address
        self.pair_justworks(
            hci_packets.IoCapabilityRequestReplyBuilder(
                dut_address.decode('utf8'),
                hci_packets.IoCapability.DISPLAY_YES_NO,
                hci_packets.OobDataPresent.NOT_PRESENT, hci_packets.
                AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION),
            security_facade.UiMsgType.DISPLAY_YES_NO_WITH_VALUE)
