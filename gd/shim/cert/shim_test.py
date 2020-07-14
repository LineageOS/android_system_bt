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

import os
import sys
import logging

from cert.event_stream import EventStream
from cert.gd_base_test import GdBaseTestClass
from cert.truth import assertThat
from facade import common_pb2 as common
from facade import rootservice_pb2 as facade_rootservice
from google.protobuf import empty_pb2 as empty_proto
from shim.facade import facade_pb2 as shim_facade


class ShimTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='SHIM', cert_module='SHIM')

    def test_dumpsys(self):
        result = self.cert.shim.Dump(empty_proto.Empty())
        result = self.dut.shim.Dump(empty_proto.Empty())
