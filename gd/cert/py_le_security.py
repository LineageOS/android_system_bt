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
from datetime import timedelta
from facade import common_pb2 as common
from google.protobuf import empty_pb2 as empty_proto
from hci.facade import facade_pb2 as hci_facade
from security.facade_pb2 import IoCapabilityMessage
from security.facade_pb2 import AuthenticationRequirementsMessage
from security.facade_pb2 import OobDataMessage
from security.facade_pb2 import UiCallbackMsg
from security.facade_pb2 import UiCallbackType


class PyLeSecurity(Closable):
    """
        Abstraction for security tasks and GRPC calls
    """

    _ui_event_stream = None
    _bond_event_stream = None

    def __init__(self, device):
        logging.info("DUT: Init")
        self._device = device
        self._device.wait_channel_ready()
        self._ui_event_stream = EventStream(
            self._device.security.FetchUiEvents(empty_proto.Empty()))
        self._bond_event_stream = EventStream(
            self._device.security.FetchBondEvents(empty_proto.Empty()))

    def wait_for_bond_event(
            self, expected_bond_event, timeout=timedelta(
                seconds=3)):  # =timedelta(seconds=DEFAULT_TIMEOUT_SECONDS)
        """
            A bond event will be triggered once the bond process
            is complete.  For the DUT we need to wait for it,
            for Cert it isn't needed.
        """
        self._bond_event_stream.assert_event_occurs(
            match_fn=lambda event: event.message_type == expected_bond_event,
            timeout=timeout)

    def close(self):
        if self._ui_event_stream is not None:
            safeClose(self._ui_event_stream)
        else:
            logging.info("DUT: UI Event Stream is None!")

        if self._bond_event_stream is not None:
            safeClose(self._bond_event_stream)
        else:
            logging.info("DUT: Bond Event Stream is None!")
