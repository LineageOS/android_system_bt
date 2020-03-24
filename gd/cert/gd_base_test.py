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

from acts import asserts
from acts.base_test import BaseTestClass
from cert.os_utils import get_gd_root, is_subprocess_alive
from facade import rootservice_pb2 as facade_rootservice


class GdBaseTestClass(BaseTestClass):

    def setup_class(self, dut_module, cert_module):
        self.dut_module = dut_module
        self.cert_module = cert_module

        gd_devices = self.controller_configs.get("GdDevice")

        self.rootcanal_running = False
        if 'rootcanal' in self.controller_configs:
            self.rootcanal_running = True
            rootcanal_logpath = os.path.join(self.log_path,
                                             'rootcanal_logs.txt')
            self.rootcanal_logs = open(rootcanal_logpath, 'w')
            rootcanal_config = self.controller_configs['rootcanal']
            rootcanal_hci_port = str(rootcanal_config.get("hci_port", "6402"))
            rootcanal = os.path.join(get_gd_root(), "root-canal")
            self.rootcanal_process = subprocess.Popen(
                [
                    rootcanal,
                    str(rootcanal_config.get("test_port", "6401")),
                    rootcanal_hci_port,
                    str(rootcanal_config.get("link_layer_port", "6403"))
                ],
                cwd=get_gd_root(),
                env=os.environ.copy(),
                stdout=self.rootcanal_logs,
                stderr=self.rootcanal_logs)
            asserts.assert_true(
                self.rootcanal_process,
                msg="Cannot start root-canal at " + str(rootcanal))
            asserts.assert_true(
                is_subprocess_alive(self.rootcanal_process),
                msg="root-canal stopped immediately after running")
            for gd_device in gd_devices:
                gd_device["rootcanal_port"] = rootcanal_hci_port
        self.register_controller(
            importlib.import_module('cert.gd_device'), builtin=True)

        self.dut = self.gd_devices[1]
        self.cert = self.gd_devices[0]

    def teardown_class(self):
        if self.rootcanal_running:
            self.rootcanal_process.send_signal(signal.SIGINT)
            rootcanal_return_code = self.rootcanal_process.wait()
            self.rootcanal_logs.close()
            if rootcanal_return_code != 0 and\
                rootcanal_return_code != -signal.SIGINT:
                logging.error(
                    "rootcanal stopped with code: %d" % rootcanal_return_code)
                return False

    def setup_test(self):
        self.dut.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    self.dut_module),))
        self.cert.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    self.cert_module),))

        self.dut.wait_channel_ready()
        self.cert.wait_channel_ready()

    def teardown_test(self):
        self.dut.rootservice.StopStack(facade_rootservice.StopStackRequest())
        self.cert.rootservice.StopStack(facade_rootservice.StopStackRequest())
