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

from datetime import timedelta

from bluetooth_packets_python3 import hci_packets
from cert.event_stream import EventStream
from cert.event_stream import IEventStream
from cert.closable import Closable
from cert.closable import safeClose
from cert.truth import assertThat
from google.protobuf import empty_pb2 as empty_proto
from hci.facade import hci_facade_pb2 as hci_facade
from neighbor.facade import facade_pb2 as neighbor_facade


class InquirySession(Closable, IEventStream):

    def __init__(self, device, inquiry_msg):
        self.inquiry_event_stream = EventStream(device.neighbor.SetInquiryMode(inquiry_msg))

    def get_event_queue(self):
        return self.inquiry_event_stream.get_event_queue()

    def close(self):
        safeClose(self.inquiry_event_stream)


class GetRemoteNameSession(Closable):

    def __init__(self, device):
        self.remote_name_stream = EventStream(device.neighbor.GetRemoteNameEvents(empty_proto.Empty()))

    def verify_name(self, name):
        assertThat(self.remote_name_stream).emits(lambda msg: bytes(name) in msg.name, timeout=timedelta(seconds=10))

    def close(self):
        safeClose(self.remote_name_stream)


class PyNeighbor(object):

    def __init__(self, device):
        self.device = device
        self.remote_host_supported_features_notification_registered = False

    def set_inquiry_mode(self, inquiry_msg):
        """
        Set the inquiry mode and return a session which can be used for event queue assertion
        """
        return InquirySession(self.device, inquiry_msg)

    def _register_remote_host_supported_features_notification(self):
        """
        REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION event will be sent when a device sends remote name request
        """
        if self.remote_host_supported_features_notification_registered:
            return
        msg = hci_facade.EventRequest(code=int(hci_packets.EventCode.REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION))
        self.device.hci.RequestEvent(msg)
        self.remote_host_supported_features_notification_registered = True

    def get_remote_name(self, remote_address):
        """
        Get the remote name and return a session which can be used for event queue assertion
        """
        self._register_remote_host_supported_features_notification()
        self.device.neighbor.ReadRemoteName(
            neighbor_facade.RemoteNameRequestMsg(
                address=remote_address.encode('utf8'), page_scan_repetition_mode=1, clock_offset=0x6855))
        return GetRemoteNameSession(self.device)
