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

import importlib
import logging
import os
import signal
import subprocess
import traceback

from functools import wraps
from grpc import RpcError

from acts import asserts, signals
from acts.context import get_current_context
from acts.base_test import BaseTestClass

from cert.async_subprocess_logger import AsyncSubprocessLogger
from cert.os_utils import get_gd_root
from cert.os_utils import read_crash_snippet_and_log_tail
from cert.os_utils import is_subprocess_alive
from cert.os_utils import make_ports_available
from cert.os_utils import TerminalColor
from cert.gd_device import ACTS_CONTROLLER_CONFIG_NAME as CONTROLLER_CONFIG_NAME
from facade import rootservice_pb2 as facade_rootservice


class GdBaseTestClass(BaseTestClass):

    SUBPROCESS_WAIT_TIMEOUT_SECONDS = 10

    def setup_class(self, dut_module, cert_module):
        self.dut_module = dut_module
        self.cert_module = cert_module
        self.log_path_base = get_current_context().get_full_output_path()
        self.verbose_mode = bool(self.user_params.get('verbose_mode', False))
        for config in self.controller_configs[CONTROLLER_CONFIG_NAME]:
            config['verbose_mode'] = self.verbose_mode

        # Start root-canal if needed
        self.rootcanal_running = False
        if 'rootcanal' in self.controller_configs:
            self.rootcanal_running = True
            # Get root canal binary
            rootcanal = os.path.join(get_gd_root(), "root-canal")
            asserts.assert_true(os.path.isfile(rootcanal), "Root canal does not exist at %s" % rootcanal)

            # Get root canal log
            self.rootcanal_logpath = os.path.join(self.log_path_base, 'rootcanal_logs.txt')
            # Make sure ports are available
            rootcanal_config = self.controller_configs['rootcanal']
            rootcanal_test_port = int(rootcanal_config.get("test_port", "6401"))
            rootcanal_hci_port = int(rootcanal_config.get("hci_port", "6402"))
            rootcanal_link_layer_port = int(rootcanal_config.get("link_layer_port", "6403"))
            asserts.assert_true(
                make_ports_available((rootcanal_test_port, rootcanal_hci_port, rootcanal_link_layer_port)),
                "Failed to make root canal ports available")

            # Start root canal process
            rootcanal_cmd = [
                rootcanal, str(rootcanal_test_port),
                str(rootcanal_hci_port),
                str(rootcanal_link_layer_port)
            ]
            self.log.debug("Running %s" % " ".join(rootcanal_cmd))
            self.rootcanal_process = subprocess.Popen(
                rootcanal_cmd,
                cwd=get_gd_root(),
                env=os.environ.copy(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True)
            asserts.assert_true(self.rootcanal_process, msg="Cannot start root-canal at " + str(rootcanal))
            asserts.assert_true(
                is_subprocess_alive(self.rootcanal_process), msg="root-canal stopped immediately after running")

            self.rootcanal_logger = AsyncSubprocessLogger(
                self.rootcanal_process, [self.rootcanal_logpath],
                log_to_stdout=self.verbose_mode,
                tag="rootcanal",
                color=TerminalColor.MAGENTA)

            # Modify the device config to include the correct root-canal port
            for gd_device_config in self.controller_configs.get("GdDevice"):
                gd_device_config["rootcanal_port"] = str(rootcanal_hci_port)

        # Parse and construct GD device objects
        self.register_controller(importlib.import_module('cert.gd_device'), builtin=True)
        self.dut = self.gd_devices[1]
        self.cert = self.gd_devices[0]

    def teardown_class(self):
        if self.rootcanal_running:
            stop_signal = signal.SIGINT
            self.rootcanal_process.send_signal(stop_signal)
            try:
                return_code = self.rootcanal_process.wait(timeout=self.SUBPROCESS_WAIT_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                logging.error("Failed to interrupt root canal via SIGINT, sending SIGKILL")
                stop_signal = signal.SIGKILL
                self.rootcanal_process.kill()
                try:
                    return_code = self.rootcanal_process.wait(timeout=self.SUBPROCESS_WAIT_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired:
                    logging.error("Failed to kill root canal")
                    return_code = -65536
            if return_code != 0 and return_code != -stop_signal:
                logging.error("rootcanal stopped with code: %d" % return_code)
            self.rootcanal_logger.stop()

    def setup_test(self):
        self.dut.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(self.dut_module),))
        self.cert.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(self.cert_module),))

        self.dut.wait_channel_ready()
        self.cert.wait_channel_ready()

    def teardown_test(self):
        self.cert.rootservice.StopStack(facade_rootservice.StopStackRequest())
        self.dut.rootservice.StopStack(facade_rootservice.StopStackRequest())

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        if not callable(attr) or not GdBaseTestClass.__is_entry_function(name):
            return attr

        @wraps(attr)
        def __wrapped(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            except RpcError as e:
                exception_info = "".join(traceback.format_exception(e.__class__, e, e.__traceback__))
                raise signals.TestFailure(
                    "RpcError during test\n\nRpcError:\n\n%s\n%s" % (exception_info, self.__dump_crashes()))

        return __wrapped

    __ENTRY_METHODS = {"setup_class", "teardown_class", "setup_test", "teardown_test"}

    @staticmethod
    def __is_entry_function(name):
        return name.startswith("test_") or name in GdBaseTestClass.__ENTRY_METHODS

    def __dump_crashes(self):
        """
        :return: formatted stack traces if found, or last few lines of log
        """
        dut_crash, dut_log_tail = self.dut.get_crash_snippet_and_log_tail()
        cert_crash, cert_log_tail = self.cert.get_crash_snippet_and_log_tail()
        rootcanal_crash = None
        rootcanal_log_tail = None
        if self.rootcanal_running and not is_subprocess_alive(self.rootcanal_process):
            rootcanal_crash, roocanal_log_tail = read_crash_snippet_and_log_tail(self.rootcanal_logpath)

        crash_detail = ""
        if dut_crash or cert_crash or rootcanal_crash:
            if rootcanal_crash:
                crash_detail += "rootcanal crashed:\n\n%s\n\n" % rootcanal_crash
            if dut_crash:
                crash_detail += "dut stack crashed:\n\n%s\n\n" % dut_crash
            if cert_crash:
                crash_detail += "cert stack crashed:\n\n%s\n\n" % cert_crash
        else:
            if rootcanal_log_tail:
                crash_detail += "rootcanal log tail:\n\n%s\n\n" % rootcanal_log_tail
            if dut_log_tail:
                crash_detail += "dut log tail:\n\n%s\n\n" % dut_log_tail
            if cert_log_tail:
                crash_detail += "cert log tail:\n\n%s\n\n" % cert_log_tail

        return crash_detail
