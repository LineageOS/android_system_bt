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
import os
import signal
import sys
import subprocess

ANDROID_BUILD_TOP = os.environ.get('ANDROID_BUILD_TOP')

sys.path.append(ANDROID_BUILD_TOP + '/out/soong/.intermediates/system/bt/gd/BluetoothCertFacadeGeneratedStub_py/gen')

ANDROID_HOST_OUT = os.environ.get('ANDROID_HOST_OUT')
ROOTCANAL = ANDROID_HOST_OUT + "/nativetest64/root-canal/root-canal"

class GdBaseTestClass(BaseTestClass):
    def __init__(self, configs):
        BaseTestClass.__init__(self, configs)

        log_path_base = configs.get('log_path', '/tmp/logs')
        rootcanal_logpath = os.path.join(log_path_base, 'rootcanal_logs.txt')
        self.rootcanal_logs = open(rootcanal_logpath, 'w')

        rootcanal_config = configs["testbed_configs"]['rootcanal']
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
            stderr=self.rootcanal_logs
        )

        gd_devices = self.testbed_configs.get("GdDevice")
        for gd_device in gd_devices:
            gd_device["rootcanal_port"] = rootcanal_hci_port

        self.register_controller(
            importlib.import_module('cert.gd_device'),
            builtin=True)

    def teardown_class(self):
        self.rootcanal_process.send_signal(signal.SIGINT)
        self.rootcanal_logs.close()

