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
from cert.captures import HciCaptures
from cert.closable import safeClose
from cert.event_stream import EventStream
from cert.matchers import HciMatchers
from cert.py_hci import PyHci
from cert.py_security import PySecurity
from cert.truth import assertThat
from datetime import datetime
from google.protobuf import empty_pb2 as empty_proto
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
    _auth_reqs = hci_packets.AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION
    _secure_connections_enabled = False

    _hci = None

    MAX_PIN_LENGTH = 16
    MIN_PIN_LENGTH = 1

    def _enqueue_hci_command(self, command, expect_complete):
        if (expect_complete):
            self._hci.send_command(command)
        else:
            self._hci.send_command(command)

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
            hci_packets.EventCode.CENTRAL_LINK_KEY_COMPLETE, hci_packets.EventCode.RETURN_LINK_KEYS,
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

    def get_oob_data_from_controller(self, pb_oob_data_type):
        """
            Get the Out-of-band data for SSP pairing

            :param pb_oob_data_type: Type of data needed
            :return: a tuple of bytes (192c,192r,256c,256r) with increasing security; bytes may be all 0s depending on pb_oob_data_type value

        """
        oob_data_type = self._oob_present_lookup[pb_oob_data_type]

        if (oob_data_type == hci_packets.OobDataPresent.NOT_PRESENT):
            logging.warn("No data present, no need to call get_oob_data")
            return ([0 for i in range(0, 16)], [0 for i in range(0, 16)], [0 for i in range(0, 16)],
                    [0 for i in range(0, 16)])

        logging.info("Cert: Requesting OOB data")
        if oob_data_type == hci_packets.OobDataPresent.P_192_PRESENT:
            # If host and controller supports secure connections we always used ReadLocalOobExtendedDataRequest
            if self._secure_connections_enabled:
                logging.info("Cert: Requesting P192 Data; secure connections")
                complete_capture = HciCaptures.ReadLocalOobExtendedDataCompleteCapture()
                self._enqueue_hci_command(hci_packets.ReadLocalOobExtendedDataBuilder(), True)
                logging.info("Cert: Waiting for OOB response from controller")
                assertThat(self._hci_event_stream).emits(complete_capture)
                command_complete = complete_capture.get()
                complete = hci_packets.ReadLocalOobExtendedDataCompleteView(command_complete)
                return (list(complete.GetC192()), list(complete.GetR192()), [0 for i in range(0, 16)],
                        [0 for i in range(0, 16)])
            # else we use ReadLocalDataRequest
            else:
                logging.info("Cert: Requesting P192 Data; no secure connections")
                complete_capture = HciCaptures.ReadLocalOobDataCompleteCapture()
                self._enqueue_hci_command(hci_packets.ReadLocalOobDataBuilder(), True)
                logging.info("Cert: Waiting for OOB response from controller")
                assertThat(self._hci_event_stream).emits(complete_capture)
                command_complete = complete_capture.get()
                complete = hci_packets.ReadLocalOobDataCompleteView(command_complete)
                return (list(complete.GetC()), list(complete.GetR()), [0 for i in range(0, 16)],
                        [0 for i in range(0, 16)])

        # Must be secure connection compatible to use these
        elif oob_data_type == hci_packets.OobDataPresent.P_256_PRESENT:
            logging.info("Cert: Requesting P256 Extended Data; secure connections")
            complete_capture = HciCaptures.ReadLocalOobExtendedDataCompleteCapture()
            self._enqueue_hci_command(hci_packets.ReadLocalOobExtendedDataBuilder(), True)
            logging.info("Cert: Waiting for OOB response from controller")
            assertThat(self._hci_event_stream).emits(complete_capture)
            command_complete = complete_capture.get()
            complete = hci_packets.ReadLocalOobExtendedDataCompleteView(command_complete)
            return ([0 for i in range(0, 16)], [0 for i in range(0, 16)], list(complete.GetC256()),
                    list(complete.GetR256()))

        else:  # Both
            logging.info("Cert: Requesting P192 AND P256 Extended Data; secure connections")
            complete_capture = HciCaptures.ReadLocalOobExtendedDataCompleteCapture()
            self._enqueue_hci_command(hci_packets.ReadLocalOobExtendedDataBuilder(), True)
            logging.info("Cert: Waiting for OOB response from controller")
            assertThat(self._hci_event_stream).emits(complete_capture)
            command_complete = complete_capture.get()
            complete = hci_packets.ReadLocalOobExtendedDataCompleteView(command_complete)
            return (list(complete.GetC192()), list(complete.GetR192()), list(complete.GetC256()),
                    list(complete.GetR256()))

    def input_passkey(self, address, passkey):
        """
            Pretend to answer the pairing dialog as a user
        """
        logging.info("Cert: Waiting for PASSKEY request")
        assertThat(self._hci_event_stream).emits(HciMatchers.EventWithCode(hci_packets.EventCode.USER_PASSKEY_REQUEST))
        logging.info("Cert: Send user input passkey %d for %s" % (passkey, address))
        peer = address.decode('utf-8')
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.ENTRY_STARTED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.CLEARED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ERASED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.DIGIT_ENTERED), True)
        self._enqueue_hci_command(
            hci_packets.SendKeypressNotificationBuilder(peer, hci_packets.KeypressNotificationType.ENTRY_COMPLETED),
            True)
        self._enqueue_hci_command(hci_packets.UserPasskeyRequestReplyBuilder(peer, passkey), True)

    def input_pin(self, address, pin):
        """
            Pretend to answer the pairing dialog as a user
        """

        if len(pin) > self.MAX_PIN_LENGTH or len(pin) < self.MIN_PIN_LENGTH:
            raise Exception("Pin code must be within range")

        logging.info("Cert: Waiting for PIN request")
        assertThat(self._hci_event_stream).emits(HciMatchers.PinCodeRequest())
        logging.info("Cert: Send user input PIN %s for %s" % (pin.decode(), address))
        peer = address.decode('utf-8')
        pin_list = list(pin)
        # Pad
        for i in range(self.MAX_PIN_LENGTH - len(pin_list)):
            pin_list.append(0)
        self._enqueue_hci_command(hci_packets.PinCodeRequestReplyBuilder(peer, len(pin), pin_list), True)

    def __send_ui_callback(self, address, callback_type, b, uid, pin):
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
        assertThat(self._hci_event_stream).emits(
            HciMatchers.CommandComplete(hci_packets.OpCode.WRITE_SIMPLE_PAIRING_MODE))

    def enable_secure_connections(self):
        """
            This is called when you want to enable secure connections support
        """
        logging.info("Cert: Sending WRITE_SECURE_CONNECTIONS_HOST_SUPPORT [True]")
        self._enqueue_hci_command(
            hci_packets.WriteSecureConnectionsHostSupportBuilder(hci_packets.Enable.ENABLED), True)
        logging.info("Cert: Waiting for controller response")
        assertThat(self._hci_event_stream).emits(
            HciMatchers.CommandComplete(hci_packets.OpCode.WRITE_SECURE_CONNECTIONS_HOST_SUPPORT))
        # TODO(optedoblivion): Figure this out and remove (see classic_pairing_handler.cc)
        #self._secure_connections_enabled = True

    def send_io_caps(self, address):
        logging.info("Cert: Waiting for IO_CAPABILITY_REQUEST")
        assertThat(self._hci_event_stream).emits(HciMatchers.IoCapabilityRequest())
        logging.info("Cert: Sending IO_CAPABILITY_REQUEST_REPLY")
        oob_data_present = hci_packets.OobDataPresent.NOT_PRESENT
        self._enqueue_hci_command(
            hci_packets.IoCapabilityRequestReplyBuilder(
                address.decode('utf8'), self._io_caps, oob_data_present, self._auth_reqs), True)

    def accept_pairing(self, dut_address, reply_boolean):
        """
            Here we handle the pairing events at the HCI level
        """
        logging.info("Cert: Waiting for LINK_KEY_REQUEST")
        assertThat(self._hci_event_stream).emits(HciMatchers.LinkKeyRequest())
        logging.info("Cert: Sending LINK_KEY_REQUEST_NEGATIVE_REPLY")
        self._enqueue_hci_command(hci_packets.LinkKeyRequestNegativeReplyBuilder(dut_address.decode('utf8')), True)
        self.send_io_caps(dut_address)
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

    def accept_oob_pairing(self, dut_address):
        logging.info("Cert: Waiting for IO_CAPABILITY_RESPONSE")
        assertThat(self._hci_event_stream).emits(HciMatchers.IoCapabilityResponse())
        self.send_io_caps(dut_address)
        logging.info("Cert: Waiting for SIMPLE_PAIRING_COMPLETE")
        ssp_complete_capture = HciCaptures.SimplePairingCompleteCapture()
        assertThat(self._hci_event_stream).emits(ssp_complete_capture)
        ssp_complete = ssp_complete_capture.get()
        logging.info(ssp_complete.GetStatus())
        assertThat(ssp_complete.GetStatus()).isEqualTo(hci_packets.ErrorCode.SUCCESS)

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
