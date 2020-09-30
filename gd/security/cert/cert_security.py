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
from cert.closable import safeClose
from cert.event_stream import EventStream
from cert.matchers import HciMatchers
from cert.py_hci import PyHci
from cert.py_security import PySecurity
from cert.truth import assertThat
from datetime import datetime
from google.protobuf import empty_pb2 as empty_proto
from hci.facade import facade_pb2 as hci_facade
from l2cap.classic import facade_pb2 as l2cap_facade
from security.facade_pb2 import IoCapabilities
from security.facade_pb2 import AuthenticationRequirements
from security.facade_pb2 import OobDataPresent


class CertSecurity(PySecurity):
    """
        Contain all of the certification stack logic for sending and receiving
        HCI commands following the Classic Pairing flows.
    """
    _io_cap_lookup = {
        IoCapabilities.DISPLAY_ONLY: hci_packets.IoCapability.DISPLAY_ONLY,
        IoCapabilities.DISPLAY_YES_NO_IO_CAP: hci_packets.IoCapability.DISPLAY_YES_NO,
        IoCapabilities.KEYBOARD_ONLY: hci_packets.IoCapability.KEYBOARD_ONLY,
        IoCapabilities.NO_INPUT_NO_OUTPUT: hci_packets.IoCapability.NO_INPUT_NO_OUTPUT,
    }

    _auth_req_lookup = {
        AuthenticationRequirements.NO_BONDING:
        hci_packets.AuthenticationRequirements.NO_BONDING,
        AuthenticationRequirements.NO_BONDING_MITM_PROTECTION:
        hci_packets.AuthenticationRequirements.NO_BONDING_MITM_PROTECTION,
        AuthenticationRequirements.DEDICATED_BONDING:
        hci_packets.AuthenticationRequirements.DEDICATED_BONDING,
        AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION:
        hci_packets.AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION,
        AuthenticationRequirements.GENERAL_BONDING:
        hci_packets.AuthenticationRequirements.GENERAL_BONDING,
        AuthenticationRequirements.GENERAL_BONDING_MITM_PROTECTION:
        hci_packets.AuthenticationRequirements.GENERAL_BONDING_MITM_PROTECTION,
    }

    _oob_present_lookup = {
        OobDataPresent.NOT_PRESENT: hci_packets.OobDataPresent.NOT_PRESENT,
        OobDataPresent.P192_PRESENT: hci_packets.OobDataPresent.P_192_PRESENT,
        OobDataPresent.P256_PRESENT: hci_packets.OobDataPresent.P_256_PRESENT,
        OobDataPresent.P192_AND_256_PRESENT: hci_packets.OobDataPresent.P_192_AND_256_PRESENT,
    }

    _hci_event_stream = None
    _io_caps = hci_packets.IoCapability.DISPLAY_ONLY
    _oob_data = hci_packets.OobDataPresent.NOT_PRESENT
    _auth_reqs = hci_packets.AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION

    _hci = None

    def _enqueue_hci_command(self, command, expect_complete):
        if (expect_complete):
            self._hci.send_command_with_complete(command)
        else:
            self._hci.send_command_with_status(command)

    def __init__(self, device):
        """
            Don't call super b/c the gRPC stream setup will crash test
        """
        logging.info("Cert: Init")
        self._device = device
        self._device.wait_channel_ready()
        self._hci = PyHci(device)
        self._hci.register_for_events(
            hci_packets.EventCode.ENCRYPTION_CHANGE, hci_packets.EventCode.CHANGE_CONNECTION_LINK_KEY_COMPLETE,
            hci_packets.EventCode.MASTER_LINK_KEY_COMPLETE, hci_packets.EventCode.RETURN_LINK_KEYS,
            hci_packets.EventCode.PIN_CODE_REQUEST, hci_packets.EventCode.LINK_KEY_REQUEST,
            hci_packets.EventCode.LINK_KEY_NOTIFICATION, hci_packets.EventCode.ENCRYPTION_KEY_REFRESH_COMPLETE,
            hci_packets.EventCode.IO_CAPABILITY_REQUEST, hci_packets.EventCode.IO_CAPABILITY_RESPONSE,
            hci_packets.EventCode.REMOTE_OOB_DATA_REQUEST, hci_packets.EventCode.SIMPLE_PAIRING_COMPLETE,
            hci_packets.EventCode.USER_PASSKEY_NOTIFICATION, hci_packets.EventCode.KEYPRESS_NOTIFICATION,
            hci_packets.EventCode.USER_CONFIRMATION_REQUEST, hci_packets.EventCode.USER_PASSKEY_REQUEST,
            hci_packets.EventCode.REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION)
        self._hci_event_stream = self._hci.get_event_stream()

    def create_bond(self, address, type):
        """
            Creates a bond from the cert perspective
        """
        logging.info("Cert: Creating bond to '%s' from '%s'" % (str(address), str(self._device.address)))
        # TODO(optedoblivion): Trigger connection to Send AuthenticationRequested

    def remove_bond(self, address, type):
        """
            We store the link key locally in the test and pretend
            So to remove_bond we need to Remove the "stored" data
        """
        pass

    def set_io_capabilities(self, io_capabilities):
        """
            Set the IO Capabilities used for the cert
        """
        logging.info("Cert: setting IO Capabilities data to '%s'" % self._io_capabilities_name_lookup.get(
            io_capabilities, "ERROR"))
        self._io_caps = self._io_cap_lookup.get(io_capabilities, hci_packets.IoCapability.DISPLAY_ONLY)

    def set_authentication_requirements(self, auth_reqs):
        """
            Establish authentication requirements for the stack
        """
        logging.info("Cert: setting Authentication Requirements data to '%s'" % self._auth_reqs_name_lookup.get(
            auth_reqs, "ERROR"))
        self._auth_reqs = self._auth_req_lookup.get(auth_reqs, hci_packets.AuthenticationRequirements.GENERAL_BONDING)

    def set_oob_data(self, data):
        """
            Set the Out-of-band data for SSP pairing
        """
        logging.info("Cert: setting OOB data present to '%s'" % data)
        self._oob_data = self._oob_present_lookup.get(data, hci_packets.OobDataPresent.NOT_PRESENT)

    def send_ui_callback(self, address, callback_type, b, uid):
        """
            Pretend to answer the pairing dailog as a user
        """
        logging.info("Cert: Send user input callback uid:%d; response: %s" % (uid, b))
        # TODO(optedoblivion): Make callback and set it to the module

    def enable_secure_simple_pairing(self):
        """
            This is called when you want to enable SSP for testing
        """
        logging.info("Cert: Sending WRITE_SIMPLE_PAIRING_MODE [True]")
        self._enqueue_hci_command(hci_packets.WriteSimplePairingModeBuilder(hci_packets.Enable.ENABLED), True)
        logging.info("Cert: Waiting for controller response")
        assertThat(self._hci_event_stream).emits(lambda msg: b'\x0e\x04\x01\x56\x0c' in msg.event)

    def accept_pairing(self, dut_address, reply_boolean):
        """
            Here we handle the pairing events at the HCI level
        """
        logging.info("Cert: Waiting for LINK_KEY_REQUEST")
        assertThat(self._hci_event_stream).emits(HciMatchers.LinkKeyRequest())
        logging.info("Cert: Sending LINK_KEY_REQUEST_NEGATIVE_REPLY")
        self._enqueue_hci_command(hci_packets.LinkKeyRequestNegativeReplyBuilder(dut_address.decode('utf8')), True)
        logging.info("Cert: Waiting for IO_CAPABILITY_REQUEST")
        assertThat(self._hci_event_stream).emits(HciMatchers.IoCapabilityRequest())
        logging.info("Cert: Sending IO_CAPABILITY_REQUEST_REPLY")
        self._enqueue_hci_command(
            hci_packets.IoCapabilityRequestReplyBuilder(
                dut_address.decode('utf8'), self._io_caps, self._oob_data, self._auth_reqs), True)
        logging.info("Cert: Waiting for USER_CONFIRMATION_REQUEST")
        assertThat(self._hci_event_stream).emits(HciMatchers.UserConfirmationRequest())
        logging.info("Cert: Sending Simulated User Response '%s'" % reply_boolean)
        if reply_boolean:
            logging.info("Cert: Sending USER_CONFIRMATION_REQUEST_REPLY")
            self._enqueue_hci_command(hci_packets.UserConfirmationRequestReplyBuilder(dut_address.decode('utf8')), True)
            logging.info("Cert: Waiting for SIMPLE_PAIRING_COMPLETE")
            assertThat(self._hci_event_stream).emits(HciMatchers.SimplePairingComplete())
            logging.info("Cert: Waiting for LINK_KEY_NOTIFICATION")
            assertThat(self._hci_event_stream).emits(HciMatchers.LinkKeyNotification())
        else:
            logging.info("Cert: Sending USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY")
            self._enqueue_hci_command(
                hci_packets.UserConfirmationRequestNegativeReplyBuilder(dut_address.decode('utf8')), True)
            logging.info("Cert: Waiting for SIMPLE_PAIRING_COMPLETE")
            assertThat(self._hci_event_stream).emits(HciMatchers.SimplePairingComplete())

    def on_user_input(self, dut_address, reply_boolean, expected_ui_event):
        """
            Cert doesn't need the test to respond to the ui event
            Cert responds in accept pairing
        """
        pass

    def wait_for_bond_event(self, expected_bond_event):
        """
            A bond event will be triggered once the bond process
            is complete.  For the DUT we need to wait for it,
            for Cert it isn't needed.
        """
        pass

    def enforce_security_policy(self, address, type, policy):
        """
            Pass for now
        """
        pass

    def wait_for_enforce_security_event(self, expected_enforce_security_event):
        """
            Cert side needs to pass
        """
        pass

    def wait_for_disconnect_event(self):
        """
            Cert side needs to pass
        """
        logging.info("Cert: Waiting for DISCONNECT_COMPLETE")
        assertThat(self._hci_event_stream).emits(HciMatchers.DisconnectionComplete())

    def close(self):
        safeClose(self._hci)
