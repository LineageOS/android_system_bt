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

from google.protobuf import empty_pb2 as empty_proto
from cert.event_stream import EventStream
from captures import ReadBdAddrCompleteCapture
from captures import ConnectionCompleteCapture
from captures import ConnectionRequestCapture
from bluetooth_packets_python3 import hci_packets
from cert.truth import assertThat
from hci.facade import facade_pb2 as hci_facade


class PyAclManager(object):

    def __init__(self, device):
        self.device = device

        self.acl_stream = EventStream(
            self.device.hci_acl_manager.FetchAclData(empty_proto.Empty()))

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.clean_up()
        return traceback is None

    def __del__(self):
        self.clean_up()

    def clean_up(self):
        self.acl_stream.shutdown()

    def get_acl_stream(self):
        return self.acl_stream
