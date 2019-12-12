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

from acts.base_test import BaseTestClass

import importlib
import logging
import os
import signal
import sys
import subprocess

ANDROID_BUILD_TOP = os.environ.get('ANDROID_BUILD_TOP')

sys.path.append(
    ANDROID_BUILD_TOP +
    '/out/soong/.intermediates/system/bt/gd/BluetoothFacadeAndCertGeneratedStub_py/gen'
)

ANDROID_HOST_OUT = os.environ.get('ANDROID_HOST_OUT')
ROOTCANAL = ANDROID_HOST_OUT + "/nativetest64/root-canal/root-canal"


class GdFacadeOnlyBaseTestClass(BaseTestClass):

    def __init__(self, configs):
        BaseTestClass.__init__(self, configs)

        log_path_base = configs.log_path
        gd_devices = self.controller_configs.get("GdDevice")

        self.rootcanal_running = False
        if 'rootcanal' in self.controller_configs:
            self.rootcanal_running = True
            rootcanal_logpath = os.path.join(log_path_base,
                                             'rootcanal_logs.txt')
            self.rootcanal_logs = open(rootcanal_logpath, 'w')
            rootcanal_config = self.controller_configs['rootcanal']
            rootcanal_hci_port = str(rootcanal_config.get("hci_port", "6402"))
            self.rootcanal_process = subprocess.Popen(
                [
                    ROOTCANAL,
                    str(rootcanal_config.get("test_port", "6401")),
                    rootcanal_hci_port,
                    str(rootcanal_config.get("link_layer_port", "6403"))
                ],
                cwd=ANDROID_BUILD_TOP,
                env=os.environ.copy(),
                stdout=self.rootcanal_logs,
                stderr=self.rootcanal_logs)
            for gd_device in gd_devices:
                gd_device["rootcanal_port"] = rootcanal_hci_port

        self.register_controller(
            importlib.import_module('cert.gd_device'), builtin=True)

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
