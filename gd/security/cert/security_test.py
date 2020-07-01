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

import time

from bluetooth_packets_python3 import hci_packets
from cert.event_stream import EventStream
from cert.gd_base_test import GdBaseTestClass
from cert.py_security import PySecurity
from facade import common_pb2 as common
from google.protobuf import empty_pb2 as empty_proto
from hci.facade import controller_facade_pb2 as controller_facade
from l2cap.classic.facade_pb2 import ClassicSecurityPolicy
from neighbor.facade import facade_pb2 as neighbor_facade
from security.cert.cert_security import CertSecurity
from security.facade_pb2 import AuthenticationRequirements
from security.facade_pb2 import BondMsgType
from security.facade_pb2 import IoCapabilities
from security.facade_pb2 import OobDataPresent
from security.facade_pb2 import UiMsgType


class SecurityTest(GdBaseTestClass):
    """
        Collection of tests that each sample results from 
        different (unique) combinations of io capabilities, authentication requirements, and oob data.
    """

    def setup_class(self):
        super().setup_class(dut_module='SECURITY', cert_module='L2CAP')

    def setup_test(self):
        super().setup_test()

        self.dut.neighbor.EnablePageScan(neighbor_facade.EnableMsg(enabled=True))
        self.cert.neighbor.EnablePageScan(neighbor_facade.EnableMsg(enabled=True))

        self.dut.name = b'DUT Device'
        self.dut.address = self.dut.hci_controller.GetMacAddress(empty_proto.Empty()).address
        self.cert.name = b'Cert Device'
        self.cert.address = self.cert.hci_controller.GetMacAddress(empty_proto.Empty()).address

        # TODO(optedoblivion): Make this happen in PySecurity or GdDevice
        self.dut.hci_controller.WriteLocalName(controller_facade.NameMsg(name=self.dut.name))
        self.cert.hci_controller.WriteLocalName(controller_facade.NameMsg(name=self.cert.name))

        self.dut_security = PySecurity(self.dut)
        self.cert_security = CertSecurity(self.cert)

    def teardown_test(self):
        self.dut_security.close()
        self.cert_security.close()
        super().teardown_test()

    # Initiates the numeric comparison test
    def _run_ssp_numeric_comparison(self, initiator, responder, init_ui_response, resp_ui_response,
                                    expected_init_ui_event, expected_resp_ui_event, expected_init_bond_event,
                                    expected_resp_bond_event):
        initiator.enable_secure_simple_pairing()
        responder.enable_secure_simple_pairing()
        initiator.create_bond(responder.get_address(), common.BluetoothAddressTypeEnum.PUBLIC_DEVICE_ADDRESS)
        self._verify_ssp_numeric_comparison(initiator, responder, init_ui_response, resp_ui_response,
                                            expected_init_ui_event, expected_resp_ui_event, expected_init_bond_event,
                                            expected_resp_bond_event)

    # Verifies the events for the numeric comparion test
    def _verify_ssp_numeric_comparison(self, initiator, responder, init_ui_response, resp_ui_response,
                                       expected_init_ui_event, expected_resp_ui_event, expected_init_bond_event,
                                       expected_resp_bond_event):
        responder.accept_pairing(initiator.get_address(), resp_ui_response)
        initiator.on_user_input(responder.get_address(), init_ui_response, expected_init_ui_event)
        initiator.wait_for_bond_event(expected_init_bond_event)
        responder.wait_for_bond_event(expected_resp_bond_event)

    def test_setup_teardown(self):
        """
            Make sure our setup and teardown is sane
        """
        pass

###### JustWorks (Numeric Comparison w/ no UI) ######
## Needs dialog as per security a bug unless pairing is temporary

# display_only + display_only is JustWorks no confirmation

    def test_dut_initiated_display_only_display_only(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.DISPLAY_ONLY)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_ONLY)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # display_yes_no + display_only is JustWorks no confirmation
    def test_dut_initiated_display_yes_no_display_only(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_ONLY)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=UiMsgType.DISPLAY_YES_NO_WITH_VALUE,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # no_input_no_output + display_only is JustWorks no confirmation
    def test_dut_initiated_no_input_no_output_display_only(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_ONLY)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # display_only + display_yes_no is JustWorks no confirmation
    def test_dut_initiated_display_only_display_yes_no(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.DISPLAY_ONLY)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # display_yes_no + display_yes_no is JustWorks no confirmation
    def test_dut_initiated_display_yes_no_display_yes_no(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=UiMsgType.DISPLAY_YES_NO_WITH_VALUE,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # display_yes_no + display_yes_no is JustWorks no confirmation
    def test_dut_initiated_display_yes_no_display_yes_no_init_reject(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=False,
            resp_ui_response=True,
            expected_init_ui_event=UiMsgType.DISPLAY_YES_NO_WITH_VALUE,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BOND_FAILED,
            expected_resp_bond_event=None)

    # no_input_no_output + display_yes_no is JustWorks no confirmation
    def test_dut_initiated_no_input_no_output_display_yes_no(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # no_input_no_output + keyboard_only is JustWorks no confirmation
    def test_dut_initiated_no_input_no_output_keyboard_only(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.DISPLAY_YES_NO_IO_CAP)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # keyboard_only + display_yes_no is JustWorks no confirmation
    def test_dut_initiated_keyboard_only_no_input_no_output(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.KEYBOARD_ONLY)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # no_input_no_output + no_input_no_output is JustWorks no confirmation
    def test_dut_initiated_no_input_no_output_no_input_no_output(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # no_input_no_output + no_input_no_output is JustWorks no confirmation
    def test_dut_initiated_no_input_no_output_no_input_no_output_twice_same_acl(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

        self.dut_security.enforce_security_policy(self.cert.address,
                                                  common.BluetoothAddressTypeEnum.PUBLIC_DEVICE_ADDRESS,
                                                  ClassicSecurityPolicy.AUTHENTICATED_ENCRYPTED_TRANSPORT)

        self._verify_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

    # no_input_no_output + no_input_no_output is JustWorks no confirmation
    def test_dut_initiated_no_input_no_output_no_input_no_output_twice_with_remove_bond(self):
        # Arrange
        self.dut_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.dut_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.dut_security.set_oob_data(OobDataPresent.NOT_PRESENT)
        self.cert_security.set_io_capabilities(IoCapabilities.NO_INPUT_NO_OUTPUT)
        self.cert_security.set_authentication_requirements(AuthenticationRequirements.DEDICATED_BONDING_MITM_PROTECTION)
        self.cert_security.set_oob_data(OobDataPresent.NOT_PRESENT)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)

        self.dut_security.remove_bond(self.cert.address, common.BluetoothAddressTypeEnum.PUBLIC_DEVICE_ADDRESS)

        # Give time for ACL to disconnect
        time.sleep(1)

        # Act and Assert
        self._run_ssp_numeric_comparison(
            initiator=self.dut_security,
            responder=self.cert_security,
            init_ui_response=True,
            resp_ui_response=True,
            expected_init_ui_event=None,
            expected_resp_ui_event=None,
            expected_init_bond_event=BondMsgType.DEVICE_BONDED,
            expected_resp_bond_event=None)


## Other permutations
#def xtest_dut_initiated_display_only_display_only_local_user_deny(self)
#def xtest_dut_initiated_display_only_display_only_remote_user_deny(self)
#def xtest_dut_initiated_display_only_display_only_local_bonded(self)
#def xtest_dut_initiated_display_only_display_only_remote_bonded(self)
#def xtest_cert_initiated_display_only_display_only(self):
#def xtest_cert_initiated_display_only_display_only_local_user_deny(self)
#def xtest_cert_initiated_display_only_display_only_remote_user_deny(self)
#def xtest_cert_initiated_display_only_display_only_local_bonded(self)
#def xtest_cert_initiated_display_only_display_only_remote_bonded(self)
