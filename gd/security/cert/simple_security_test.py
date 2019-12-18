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

from datetime import timedelta
import os
import sys

sys.path.append(os.environ['ANDROID_BUILD_TOP'] + '/system/bt/gd')

from cert.gd_base_test_facade_only import GdFacadeOnlyBaseTestClass
from cert.event_callback_stream import EventCallbackStream
from cert.event_asserts import EventAsserts
from google.protobuf import empty_pb2
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from google.protobuf import empty_pb2
from security import facade_pb2 as security_facade_pb2
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from bluetooth_packets_python3 import hci_packets


class SimpleSecurityTest(GdFacadeOnlyBaseTestClass):

    def setup_test(self):
        self.cert_device = self.gd_devices[0]
        self.device_under_test = self.gd_devices[1]

        self.device_under_test.rootservice.StartStack(
            facade_rootservice_pb2.StartStackRequest(
                module_under_test=facade_rootservice_pb2.BluetoothModule.Value(
                    'SECURITY'),))
        self.cert_device.rootservice.StartStack(
            facade_rootservice_pb2.StartStackRequest(
                module_under_test=facade_rootservice_pb2.BluetoothModule.Value(
                    'L2CAP'),))

        self.device_under_test.address = self.device_under_test.controller_read_only_property.ReadLocalAddress(
            empty_pb2.Empty()).address
        self.cert_device.address = self.cert_device.controller_read_only_property.ReadLocalAddress(
            empty_pb2.Empty()).address

        self.dut_address = common_pb2.BluetoothAddress(
            address=self.device_under_test.address)
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert_device.address)

        self.dut_address_with_type = common_pb2.BluetoothAddressWithType()
        self.dut_address_with_type.address.CopyFrom(self.dut_address)
        self.dut_address_with_type.type = common_pb2.BluetoothPeerAddressTypeEnum.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS

        self.cert_address_with_type = common_pb2.BluetoothAddressWithType()
        self.cert_address_with_type.address.CopyFrom(self.cert_address)
        self.cert_address_with_type.type = common_pb2.BluetoothPeerAddressTypeEnum.PUBLIC_DEVICE_OR_IDENTITY_ADDRESS

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest())
        self.cert_device.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest())

    def test_pass(self):
        pass
