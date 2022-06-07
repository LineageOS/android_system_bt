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

from cert.async_subprocess_logger import AsyncSubprocessLogger
from cert.os_utils import get_gd_root
from cert.os_utils import read_crash_snippet_and_log_tail
from cert.os_utils import is_subprocess_alive
from cert.os_utils import make_ports_available
from cert.os_utils import TerminalColor
from cert.gd_device import MOBLY_CONTROLLER_CONFIG_NAME as CONTROLLER_CONFIG_NAME
from facade import rootservice_pb2 as facade_rootservice


def setup_class_core(dut_module, cert_module, verbose_mode, log_path_base, controller_configs):
    info = {}
    info['dut_module'] = dut_module
    info['cert_module'] = cert_module
    info['controller_configs'] = controller_configs

    # Start root-canal if needed
    info['rootcanal_running'] = False
    info['rootcanal_logpath'] = ""
    info['rootcanal_process'] = None
    info['rootcanal_logger'] = None
    if 'rootcanal' in info['controller_configs']:
        info['rootcanal_running'] = True
        # Get root canal binary
        rootcanal = os.path.join(get_gd_root(), "root-canal")
        info['rootcanal'] = rootcanal
        info['rootcanal_exist'] = os.path.isfile(rootcanal)
        if not os.path.isfile(rootcanal):
            return info

        # Get root canal log
        rootcanal_logpath = os.path.join(log_path_base, 'rootcanal_logs.txt')
        info['rootcanal_logpath'] = rootcanal_logpath
        # Make sure ports are available
        rootcanal_config = info['controller_configs']['rootcanal']
        rootcanal_test_port = int(rootcanal_config.get("test_port", "6401"))
        rootcanal_hci_port = int(rootcanal_config.get("hci_port", "6402"))
        rootcanal_link_layer_port = int(rootcanal_config.get("link_layer_port", "6403"))

        info['make_rootcanal_ports_available'] = make_ports_available((rootcanal_test_port, rootcanal_hci_port,
                                                                       rootcanal_link_layer_port))
        if not make_ports_available((rootcanal_test_port, rootcanal_hci_port, rootcanal_link_layer_port)):
            return info

        # Start root canal process
        rootcanal_cmd = [rootcanal, str(rootcanal_test_port), str(rootcanal_hci_port), str(rootcanal_link_layer_port)]
        info['rootcanal_cmd'] = rootcanal_cmd

        rootcanal_process = subprocess.Popen(
            rootcanal_cmd,
            cwd=get_gd_root(),
            env=os.environ.copy(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True)

        info['rootcanal_process'] = rootcanal_process
        if rootcanal_process:
            info['is_rootcanal_process_started'] = True
        else:
            info['is_rootcanal_process_started'] = False
            return info
        info['is_subprocess_alive'] = is_subprocess_alive(rootcanal_process)
        if not is_subprocess_alive(rootcanal_process):
            info['is_subprocess_alive'] = False
            return info

        info['rootcanal_logger'] = AsyncSubprocessLogger(
            rootcanal_process, [rootcanal_logpath],
            log_to_stdout=verbose_mode,
            tag="rootcanal",
            color=TerminalColor.MAGENTA)

        # Modify the device config to include the correct root-canal port
        for gd_device_config in info['controller_configs'].get("GdDevice"):
            gd_device_config["rootcanal_port"] = str(rootcanal_hci_port)

    return info


def teardown_class_core(rootcanal_running, rootcanal_process, rootcanal_logger, subprocess_wait_timeout_seconds):
    if rootcanal_running:
        stop_signal = signal.SIGINT
        rootcanal_process.send_signal(stop_signal)
        try:
            return_code = rootcanal_process.wait(timeout=subprocess_wait_timeout_seconds)
        except subprocess.TimeoutExpired:
            logging.error("Failed to interrupt root canal via SIGINT, sending SIGKILL")
            stop_signal = signal.SIGKILL
            rootcanal_process.kill()
            try:
                return_code = rootcanal_process.wait(timeout=subprocess_wait_timeout_seconds)
            except subprocess.TimeoutExpired:
                logging.error("Failed to kill root canal")
                return_code = -65536
        if return_code != 0 and return_code != -stop_signal:
            logging.error("rootcanal stopped with code: %d" % return_code)
        rootcanal_logger.stop()


def setup_test_core(dut, cert, dut_module, cert_module):
    dut.rootservice.StartStack(
        facade_rootservice.StartStackRequest(module_under_test=facade_rootservice.BluetoothModule.Value(dut_module),))
    cert.rootservice.StartStack(
        facade_rootservice.StartStackRequest(module_under_test=facade_rootservice.BluetoothModule.Value(cert_module),))

    dut.wait_channel_ready()
    cert.wait_channel_ready()


def teardown_test_core(cert, dut):
    cert.rootservice.StopStack(facade_rootservice.StopStackRequest())
    dut.rootservice.StopStack(facade_rootservice.StopStackRequest())


def dump_crashes_core(dut, cert, rootcanal_running, rootcanal_process, rootcanal_logpath):
    dut_crash, dut_log_tail = dut.get_crash_snippet_and_log_tail()
    cert_crash, cert_log_tail = cert.get_crash_snippet_and_log_tail()
    rootcanal_crash = None
    rootcanal_log_tail = None
    if rootcanal_running and not is_subprocess_alive(rootcanal_process):
        rootcanal_crash, roocanal_log_tail = read_crash_snippet_and_log_tail(rootcanal_logpath)

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
