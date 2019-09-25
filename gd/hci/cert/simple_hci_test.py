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
sys.path.append(os.environ['ANDROID_BUILD_TOP'] + '/system/bt/gd')

from cert.gd_base_test import GdBaseTestClass
from cert.event_stream import EventStream
from cert import rootservice_pb2 as cert_rootservice_pb2
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from google.protobuf import empty_pb2
from hci import facade_pb2 as hci_facade_pb2
from hci.cert import api_pb2 as hci_cert_pb2
from hci.cert import api_pb2_grpc as hci_cert_pb2_grpc

class SimpleHciTest(GdBaseTestClass):

    def setup_test(self):
        self.device_under_test = self.gd_devices[0]
        self.cert_device = self.gd_cert_devices[0]

        self.device_under_test.rootservice.StartStack(
            facade_rootservice_pb2.StartStackRequest(
                module_under_test=facade_rootservice_pb2.BluetoothModule.Value('HCI'),
            )
        )
        self.cert_device.rootservice.StartStack(
            cert_rootservice_pb2.StartStackRequest(
                module_to_test=cert_rootservice_pb2.BluetoothModule.Value('HCI'),
            )
        )

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

        self.device_under_test.hci.SetPageScanMode(
            hci_facade_pb2.PageScanMode(enabled=True)
        )
        self.cert_device.hci.SetPageScanMode(
            hci_cert_pb2.PageScanMode(enabled=True)
        )

        dut_address = self.device_under_test.controller_read_only_property.ReadLocalAddress(empty_pb2.Empty()).address
        self.device_under_test.address = dut_address
        cert_address = self.cert_device.controller_read_only_property.ReadLocalAddress(empty_pb2.Empty()).address
        self.cert_device.address = cert_address

        self.dut_connection_complete_stream = self.device_under_test.hci.connection_complete_stream
        self.dut_disconnection_stream = self.device_under_test.hci.disconnection_stream
        self.dut_connection_failed_stream = self.device_under_test.hci.connection_failed_stream
        self.dut_command_complete_stream = self.device_under_test.hci_classic_security.command_complete_stream

        self.dut_address = common_pb2.BluetoothAddress(
            address=self.device_under_test.address)
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert_device.address)

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest()
        )
        self.cert_device.rootservice.StopStack(
            cert_rootservice_pb2.StopStackRequest()
        )

    def test_none_event(self):
        self.dut_connection_complete_stream.clear_event_buffer()
        self.dut_connection_complete_stream.subscribe()
        self.dut_connection_complete_stream.assert_none()
        self.dut_connection_complete_stream.unsubscribe()

    def _connect_from_dut(self):
        policy = hci_cert_pb2.IncomingConnectionPolicy(
            remote=self.dut_address,
            accepted=True
        )
        self.cert_device.hci.SetIncomingConnectionPolicy(policy)

        self.dut_connection_complete_stream.subscribe()
        self.device_under_test.hci.Connect(self.cert_address)
        self.dut_connection_complete_stream.assert_event_occurs(
            lambda event: self._get_handle(event)
        )
        self.dut_connection_complete_stream.unsubscribe()

    def _disconnect_from_dut(self):
        self.dut_disconnection_stream.subscribe()
        self.device_under_test.hci.Disconnect(self.cert_address)
        self.dut_disconnection_stream.assert_event_occurs(
            lambda event: event.remote.address == self.cert_device.address
        )

    def _get_handle(self, event):
        if event.remote.address == self.cert_device.address:
            self.connection_handle = event.connection_handle
            return True
        return False

    def test_connect_disconnect_send_acl(self):
        self._connect_from_dut()

        cert_acl_stream = self.cert_device.hci.acl_stream
        cert_acl_stream.subscribe()
        acl_data = hci_facade_pb2.AclData(remote=self.cert_address, payload=b'123')
        self.device_under_test.hci.SendAclData(acl_data)
        self.device_under_test.hci.SendAclData(acl_data)
        self.device_under_test.hci.SendAclData(acl_data)
        cert_acl_stream.assert_event_occurs(
            lambda packet : b'123' in packet.payload
            and packet.remote == self.dut_address
        )
        cert_acl_stream.unsubscribe()

        self._disconnect_from_dut()

    def test_connect_disconnect_receive_acl(self):
        self._connect_from_dut()

        self.device_under_test.hci.acl_stream.subscribe()
        acl_data = hci_cert_pb2.AclData(remote=self.dut_address, payload=b'123')
        self.cert_device.hci.SendAclData(acl_data)
        self.cert_device.hci.SendAclData(acl_data)
        self.cert_device.hci.SendAclData(acl_data)
        self.device_under_test.hci.acl_stream.assert_event_occurs(
            lambda packet : b'123' in packet.payload
            and packet.remote == self.cert_address
        )
        self.device_under_test.hci.acl_stream.unsubscribe()

        self._disconnect_from_dut()

    def test_reject_connection_request(self):
        self.dut_connection_failed_stream.subscribe()
        self.device_under_test.hci.Connect(self.cert_address)
        self.dut_connection_failed_stream.assert_event_occurs(
            lambda event : event.remote == self.cert_address
        )
        self.dut_connection_failed_stream.unsubscribe()

    def test_send_classic_security_command(self):
        self._connect_from_dut()
        self.dut_command_complete_stream.subscribe()

        self.device_under_test.hci.AuthenticationRequested(self.cert_address)

        # Link request
        self.device_under_test.hci_classic_security.LinkKeyRequestNegativeReply(self.cert_address)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x040c
        )

        # Pin code request
        message = hci_facade_pb2.PinCodeRequestReplyMessage(
            remote=self.cert_address,
            len=4,
            pin_code=bytes("1234", encoding = "ASCII")
        )
        self.device_under_test.hci_classic_security.PinCodeRequestReply(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x040d
        )
        self.device_under_test.hci_classic_security.PinCodeRequestNegativeReply(self.cert_address)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x040e
        )

        # IO capability request
        message = hci_facade_pb2.IoCapabilityRequestReplyMessage(
            remote=self.cert_address,
            io_capability=0,
            oob_present=0,
            authentication_requirements=0
        )
        self.device_under_test.hci_classic_security.IoCapabilityRequestReply(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x042b
        )

        # message = hci_facade_pb2.IoCapabilityRequestNegativeReplyMessage(
        #     remote=self.cert_address,
        #     reason=1
        # )
        # # link_layer_controller.cc(447)] Check failed: security_manager_.GetAuthenticationAddress() == peer
        # self.device_under_test.hci_classic_security.IoCapabilityRequestNegativeReply(message)

        # User confirm request
        self.device_under_test.hci_classic_security.UserConfirmationRequestReply(self.cert_address)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x042c
        )

        message = hci_facade_pb2.LinkKeyRequestReplyMessage(
            remote=self.cert_address,
            link_key=bytes("4C68384139F574D836BCF34E9DFB01BF", encoding = "ASCII")
        )
        self.device_under_test.hci_classic_security.LinkKeyRequestReply(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x040b
        )

        self.device_under_test.hci_classic_security.UserConfirmationRequestNegativeReply(self.cert_address)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x042d
        )

        # User passkey request
        message = hci_facade_pb2.UserPasskeyRequestReplyMessage(
            remote=self.cert_address,
            passkey=999999,
        )
        self.device_under_test.hci_classic_security.UserPasskeyRequestReply(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x042e
        )

        self.device_under_test.hci_classic_security.UserPasskeyRequestNegativeReply(self.cert_address)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x042f
        )

        # Remote OOB data request
        message = hci_facade_pb2.RemoteOobDataRequestReplyMessage(
            remote=self.cert_address,
            c=b'\x19\x20\x21\x22\x23\x24\x25\x26\x19\x20\x21\x22\x23\x24\x25\x26',
            r=b'\x30\x31\x32\x33\x34\x35\x36\x37\x30\x31\x32\x33\x34\x35\x36\x37',
        )
        self.device_under_test.hci_classic_security.RemoteOobDataRequestReply(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0430
        )
        self.device_under_test.hci_classic_security.RemoteOobDataRequestNegativeReply(self.cert_address)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0433
        )

        # Read/Write/Delete link key
        message = hci_facade_pb2.ReadStoredLinkKeyMessage(
            remote=self.cert_address,
            read_all_flag = 0,
        )
        self.device_under_test.hci_classic_security.ReadStoredLinkKey(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c0d
        )

        message = hci_facade_pb2.WriteStoredLinkKeyMessage(
            num_keys_to_write=1,
            remote=self.cert_address,
            link_keys=bytes("4C68384139F574D836BCF34E9DFB01BF", encoding = "ASCII"),
        )
        self.device_under_test.hci_classic_security.WriteStoredLinkKey(message)

        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c11
        )

        message = hci_facade_pb2.DeleteStoredLinkKeyMessage(
            remote=self.cert_address,
            delete_all_flag = 0,
        )
        self.device_under_test.hci_classic_security.DeleteStoredLinkKey(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c12
        )

        # Refresh Encryption Key
        message = hci_facade_pb2.RefreshEncryptionKeyMessage(
            connection_handle=self.connection_handle,
        )
        self.device_under_test.hci_classic_security.RefreshEncryptionKey(message)

        # Read/Write Simple Pairing Mode
        self.device_under_test.hci_classic_security.ReadSimplePairingMode(empty_pb2.Empty())
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c55
        )

        message = hci_facade_pb2.WriteSimplePairingModeMessage(
            simple_pairing_mode=1,
        )
        self.device_under_test.hci_classic_security.WriteSimplePairingMode(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c56
        )

        # Read local oob data
        self.device_under_test.hci_classic_security.ReadLocalOobData(empty_pb2.Empty())
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c57
        )

        # Send keypress notification
        message = hci_facade_pb2.SendKeypressNotificationMessage(
            remote=self.cert_address,
            notification_type=1,
        )
        self.device_under_test.hci_classic_security.SendKeypressNotification(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c60
        )

        # Read local oob extended data
        self.device_under_test.hci_classic_security.ReadLocalOobExtendedData(empty_pb2.Empty())
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x0c7d
        )

        # Read Encryption key size
        message = hci_facade_pb2.ReadEncryptionKeySizeMessage(
            connection_handle=self.connection_handle,
        )
        self.device_under_test.hci_classic_security.ReadEncryptionKeySize(message)
        self.dut_command_complete_stream.assert_event_occurs(
            lambda event: event.command_opcode == 0x1408
        )

        self.dut_command_complete_stream.unsubscribe()
        self._disconnect_from_dut()

    def test_interal_hci_command(self):
        self._connect_from_dut()
        self.device_under_test.hci.TestInternalHciCommands(empty_pb2.Empty())
        self.device_under_test.hci.TestInternalHciLeCommands(empty_pb2.Empty())
        self._disconnect_from_dut()

    def test_classic_connection_management_command(self):
        self._connect_from_dut()
        self.device_under_test.hci.TestClassicConnectionManagementCommands(self.cert_address)
        self._disconnect_from_dut()