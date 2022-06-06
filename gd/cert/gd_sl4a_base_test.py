#!/usr/bin/env python3
#
#   Copyright 2021 - The Android Open Source Project
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
import traceback
import os
import logging

from functools import wraps
from grpc import RpcError

from acts import signals
from acts.base_test import BaseTestClass
from acts.context import get_current_context
from acts.controllers.adb_lib.error import AdbCommandError

from cert.ble_lib import enable_bluetooth, disable_bluetooth
from cert.gd_device import MOBLY_CONTROLLER_CONFIG_NAME as CONTROLLER_CONFIG_NAME
from cert.ble_lib import BleLib
from facade import rootservice_pb2 as facade_rootservice


class GdSl4aBaseTestClass(BaseTestClass):

    SUBPROCESS_WAIT_TIMEOUT_SECONDS = 10

    def setup_class(self, cert_module):
        self.log_path_base = get_current_context().get_full_output_path()
        self.verbose_mode = bool(self.user_params.get('verbose_mode', False))
        for config in self.controller_configs[CONTROLLER_CONFIG_NAME]:
            config['verbose_mode'] = self.verbose_mode
        self.cert_module = cert_module

        # Parse and construct GD device objects
        self.register_controller(importlib.import_module('cert.gd_device'), builtin=True)
        self.dut = self.android_devices[0]
        self.cert = self.gd_devices[0]

        # Enable full btsnoop log
        self.dut.adb.shell("setprop persist.bluetooth.btsnooplogmode full")
        getprop_result = self.dut.adb.shell("getprop persist.bluetooth.btsnooplogmode") == "full"
        if not getprop_result:
            self.dut.log.warning("Failed to enable Bluetooth Hci Snoop Logging.")

        self.ble = BleLib(log=self.log, dut=self.dut)

    def teardown_class(self):
        pass

    def setup_test(self):
        self.cert.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(self.cert_module),))
        self.cert.wait_channel_ready()

        self.timer_list = []
        self.dut.ed.clear_all_events()
        self.dut.droid.setScreenTimeout(500)
        self.dut.droid.wakeUpNow()

        # Always start tests with Bluetooth enabled and BLE disabled.
        self.dut.droid.bluetoothDisableBLE()
        disable_bluetooth(self.dut.droid, self.dut.ed)
        # Enable full verbose logging for Bluetooth
        self.dut.adb.shell("device_config put bluetooth INIT_logging_debug_enabled_for_all true")
        # Then enable Bluetooth
        enable_bluetooth(self.dut.droid, self.dut.ed)
        self.dut.droid.bluetoothDisableBLE()
        return True

    def teardown_test(self):
        # Make sure BLE is disabled and Bluetooth is disabled after test
        self.dut.droid.bluetoothDisableBLE()
        disable_bluetooth(self.dut.droid, self.dut.ed)
        self.cert.rootservice.StopStack(facade_rootservice.StopStackRequest())

        # TODO: split cert logcat logs into individual tests
        current_test_dir = get_current_context().get_full_output_path()

        # Pull DUT logs
        self.pull_dut_logs(current_test_dir)

        # Pull CERT logs
        self.cert.pull_logs(current_test_dir)

    def pull_dut_logs(self, base_dir):
        try:
            self.dut.pull_files("/data/misc/bluetooth/logs/btsnoop_hci.log",
                                os.path.join(base_dir, "DUT_%s_btsnoop_hci.log" % self.dut.serial))
            self.dut.pull_files("/data/misc/bluedroid/bt_config.conf",
                                os.path.join(base_dir, "DUT_%s_bt_config.conf" % self.dut.serial))
            self.dut.pull_files("/data/misc/bluedroid/bt_config.bak",
                                os.path.join(base_dir, "DUT_%s_bt_config.bak" % self.dut.serial))
        except AdbCommandError as error:
            logging.warning("Failed to pull logs from DUT: " + str(error))

    def __getattribute__(self, name):
        attr = super().__getattribute__(name)
        if not callable(attr) or not GdSl4aBaseTestClass.__is_entry_function(name):
            return attr

        @wraps(attr)
        def __wrapped(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            except RpcError as e:
                exception_info = "".join(traceback.format_exception(e.__class__, e, e.__traceback__))
                raise signals.TestFailure("RpcError during test\n\nRpcError:\n\n%s" % (exception_info))

        return __wrapped

    __ENTRY_METHODS = {"setup_class", "teardown_class", "setup_test", "teardown_test"}

    @staticmethod
    def __is_entry_function(name):
        return name.startswith("test_") or name in GdSl4aBaseTestClass.__ENTRY_METHODS
