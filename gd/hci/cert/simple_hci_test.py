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

        self.device_under_test.hci.SetPageScanMode(
            hci_facade_pb2.PageScanMode(enabled=True)
        )
        self.cert_device.hci.SetPageScanMode(
            hci_cert_pb2.PageScanMode(enabled=True)
        )

        dut_address = self.device_under_test.hci.ReadLocalAddress(empty_pb2.Empty()).address
        self.device_under_test.address = dut_address
        cert_address = self.cert_device.hci.ReadLocalAddress(empty_pb2.Empty()).address
        self.cert_device.address = cert_address

        self.dut_connection_complete_stream = self.device_under_test.hci.connection_complete_stream
        self.dut_disconnection_stream = self.device_under_test.hci.disconnection_stream
        self.dut_connection_failed_stream = self.device_under_test.hci.connection_failed_stream

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
            lambda event: event.remote.address == self.cert_device.address
        )
        self.dut_connection_complete_stream.unsubscribe()

    def _disconnect_from_dut(self):
        self.dut_disconnection_stream.subscribe()
        self.device_under_test.hci.Disconnect(self.cert_address)
        self.dut_disconnection_stream.assert_event_occurs(
            lambda event: event.remote.address == self.cert_device.address
        )

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
