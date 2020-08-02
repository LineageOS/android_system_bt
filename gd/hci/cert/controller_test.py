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

import time

from cert.gd_base_test import GdBaseTestClass
from cert.truth import assertThat
from google.protobuf import empty_pb2 as empty_proto
from facade import rootservice_pb2 as facade_rootservice
from hci.facade import controller_facade_pb2 as controller_facade


class ControllerTest(GdBaseTestClass):

    def setup_class(self):
        super().setup_class(dut_module='HCI_INTERFACES', cert_module='HCI_INTERFACES')

    def test_get_addresses(self):
        cert_address = self.cert.hci_controller.GetMacAddressSimple()
        dut_address = self.dut.hci_controller.GetMacAddressSimple()

        assertThat(cert_address).isNotEqualTo(dut_address)
        time.sleep(1)  # This shouldn't be needed b/149120542

    def test_write_local_name(self):
        self.dut.hci_controller.WriteLocalName(controller_facade.NameMsg(name=b'ImTheDUT'))
        self.cert.hci_controller.WriteLocalName(controller_facade.NameMsg(name=b'ImTheCert'))
        cert_name = self.cert.hci_controller.GetLocalNameSimple()
        dut_name = self.dut.hci_controller.GetLocalNameSimple()

        assertThat(dut_name).isEqualTo(b'ImTheDUT')
        assertThat(cert_name).isEqualTo(b'ImTheCert')
