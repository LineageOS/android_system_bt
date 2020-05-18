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

import logging

from bluetooth_packets_python3 import hci_packets
from cert.closable import Closable
from cert.closable import safeClose
from cert.event_stream import EventStream
from facade import common_pb2 as common
from google.protobuf import empty_pb2 as empty_proto
from hci.facade import facade_pb2 as hci_facade
from security.facade_pb2 import IoCapabilityMessage
from security.facade_pb2 import AuthenticationRequirementsMessage
from security.facade_pb2 import OobDataMessage
from security.facade_pb2 import UiCallbackMsg
from security.facade_pb2 import UiCallbackType


class PySecurity(Closable):
    """
        Abstraction for security tasks and GRPC calls
    """

    _ui_event_stream = None
    _bond_event_stream = None

    def __init__(self, device):
        logging.info("DUT: Init")
        self._device = device
        self._device.wait_channel_ready()
        self._ui_event_stream = EventStream(self._device.security.FetchUiEvents(empty_proto.Empty()))
        self._bond_event_stream = EventStream(self._device.security.FetchBondEvents(empty_proto.Empty()))

    def create_bond(self, address, type):
        """
            Triggers stack under test to create bond
        """
        logging.info("DUT: Creating bond to '%s' from '%s'" % (str(address), str(self._device.address)))
        self._device.security.CreateBond(
            common.BluetoothAddressWithType(address=common.BluetoothAddress(address=address), type=type))

    def remove_bond(self, address_with_type):
        """
            Removes bond from stack under test
        """
        self._device.security.RemoveBond(address_with_type)

    def set_io_capabilities(self, io_capabilities):
        """
            Set the IO Capabilities used for the DUT
        """
        logging.info("DUT: setting IO Capabilities data to '%s'" % io_capabilities)
        self._device.security.SetIoCapability(IoCapabilityMessage(capability=io_capabilities))

    def set_authentication_requirements(self, auth_reqs):
        """
            Establish authentication requirements for the stack
        """
        logging.info("DUT: setting Authentication Requirements data to '%s'" % auth_reqs)
        self._device.security.SetAuthenticationRequirements(AuthenticationRequirementsMessage(requirement=auth_reqs))

    def set_oob_data(self, data_present):
        """
            Set the Out-of-band data present flag for SSP pairing
        """
        logging.info("DUT: setting OOB data present to '%s'" % data_present)
        self._device.security.SetOobDataPresent(OobDataMessage(data_present=data_present))

    def send_ui_callback(self, address, callback_type, b, uid):
        """
            Send a callback from the UI as if the user pressed a button on the dialog
        """
        logging.info("DUT: Sending user input response uid: %d; response: %s" % (uid, b))
        self._device.security.SendUiCallback(
            UiCallbackMsg(
                message_type=callback_type,
                boolean=b,
                unique_id=uid,
                address=common.BluetoothAddressWithType(
                    address=common.BluetoothAddress(address=address),
                    type=common.BluetoothAddressTypeEnum.PUBLIC_DEVICE_ADDRESS)))

    def enable_secure_simple_pairing(self):
        """
            This is called when you want to enable SSP for testing
            Since the stack under test already enables it by default
            we do not need to do anything here for the time being
        """
        pass

    def accept_pairing(self, cert_address, reply_boolean):
        """
            Here we pass, but in cert we perform pairing flow tasks.
            This was added here in order to be more dynamic, but the stack
            under test will handle the pairing flow.
        """
        pass

    def on_user_input(self, cert_address, reply_boolean, expected_ui_event):
        """
            Respond to the UI event
        """
        if expected_ui_event is None:
            return

        ui_id = -1

        def get_unique_id(event):
            if event.message_type == expected_ui_event:
                nonlocal ui_id
                ui_id = event.unique_id
                return True
            return False

        logging.info("DUT: Waiting for expected UI event")
        self._ui_event_stream.assert_event_occurs(get_unique_id)
        # TODO(optedoblivion): Make UiCallbackType dynamic for PASSKEY when added
        self.send_ui_callback(cert_address, UiCallbackType.YES_NO, reply_boolean, ui_id)

    def get_address(self):
        return self._device.address

    def wait_for_bond_event(self, expected_bond_event):
        """
            A bond event will be triggered once the bond process
            is complete.  For the DUT we need to wait for it,
            for Cert it isn't needed.
        """
        self._bond_event_stream.assert_event_occurs(lambda event: event.message_type == expected_bond_event)

    def close(self):
        if self._ui_event_stream is not None:
            safeClose(self._ui_event_stream)
        else:
            logging.info("DUT: UI Event Stream is None!")

        if self._bond_event_stream is not None:
            safeClose(self._bond_event_stream)
        else:
            logging.info("DUT: Bond Event Stream is None!")
