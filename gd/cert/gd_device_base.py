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

import logging
import os
from builtins import open
import json
import signal
import socket
import subprocess
import time

from acts import asserts
from acts import context
from acts.controllers.adb import AdbProxy, AdbError

import grpc

from cert.os_utils import get_gd_root, is_subprocess_alive

WAIT_CHANNEL_READY_TIMEOUT = 10
WAIT_FOR_DEVICE_TIMEOUT = 180


def replace_vars(string, config):
    serial_number = config.get("serial_number")
    if serial_number is None:
        serial_number = ""
    rootcanal_port = config.get("rootcanal_port")
    if rootcanal_port is None:
        rootcanal_port = ""
    if serial_number == "DUT" or serial_number == "CERT":
        raise Exception("Did you forget to configure the serial number?")
    return string.replace("$GD_ROOT", get_gd_root()) \
                 .replace("$(grpc_port)", config.get("grpc_port")) \
                 .replace("$(grpc_root_server_port)", config.get("grpc_root_server_port")) \
                 .replace("$(rootcanal_port)", rootcanal_port) \
                 .replace("$(signal_port)", config.get("signal_port")) \
                 .replace("$(serial_number)", serial_number)


class GdDeviceBase:

    def __init__(self, grpc_port, grpc_root_server_port, signal_port, cmd,
                 label, type_identifier, serial_number, name):
        self.label = label if label is not None else grpc_port
        # logging.log_path only exists when this is used in an ACTS test run.
        self.log_path_base = context.get_current_context().get_full_output_path(
        )

        backing_process_logpath = os.path.join(
            self.log_path_base,
            '%s_%s_backing_logs.txt' % (type_identifier, label))
        self.backing_process_logs = open(backing_process_logpath, 'w')

        cmd_str = json.dumps(cmd)
        if "--btsnoop=" not in cmd_str:
            btsnoop_path = os.path.join(self.log_path_base,
                                        '%s_btsnoop_hci.log' % label)
            cmd.append("--btsnoop=" + btsnoop_path)

        self.grpc_root_server_port = int(grpc_root_server_port)
        self.grpc_port = int(grpc_port)
        self.signal_port = int(signal_port)

        self.serial_number = serial_number
        if self.serial_number:
            self.adb = AdbProxy(self.serial_number)
            self.ensure_verity_disabled()
            asserts.assert_true(
                self.adb.ensure_root(),
                msg="device %s cannot run as root after enabling verity" %
                self.serial_number)
            self.adb.shell("date " + time.strftime("%m%d%H%M%Y.%S"))
            self.tcp_forward_or_die(self.grpc_port, self.grpc_port)
            self.tcp_forward_or_die(self.grpc_root_server_port,
                                    self.grpc_root_server_port)
            self.tcp_reverse_or_die(self.signal_port, self.signal_port)
            self.push_or_die(
                os.path.join(get_gd_root(), "target",
                             "bluetooth_stack_with_facade"), "system/bin")
            self.push_or_die(
                os.path.join(get_gd_root(), "target", "libbluetooth_gd.so"),
                "system/lib64")
            self.push_or_die(
                os.path.join(get_gd_root(), "target", "libgrpc++_unsecure.so"),
                "system/lib64")
            self.ensure_no_output(self.adb.shell("logcat -c"))
            self.adb.shell("rm /data/misc/bluetooth/logs/btsnoop_hci.log")
            self.ensure_no_output(self.adb.shell("svc bluetooth disable"))

        self.name = name

        tester_signal_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tester_signal_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                                        1)
        socket_address = ('localhost', self.signal_port)
        tester_signal_socket.bind(socket_address)
        tester_signal_socket.listen(1)

        environment = os.environ.copy()
        # Enable LLVM code coverage output for host only tests
        if not self.serial_number:
            environment["LLVM_PROFILE_FILE"] = os.path.join(
                self.log_path_base,
                "%s_%s_backing_coverage.profraw" % (type_identifier, label))
        self.backing_process = subprocess.Popen(
            cmd,
            cwd=get_gd_root(),
            env=environment,
            stdout=self.backing_process_logs,
            stderr=self.backing_process_logs)
        asserts.assert_true(
            self.backing_process,
            msg="Cannot start backing_process at " + " ".join(cmd))
        asserts.assert_true(
            is_subprocess_alive(self.backing_process),
            msg="backing_process stopped immediately after running " +
            " ".join(cmd))
        tester_signal_socket.accept()
        tester_signal_socket.close()

        self.grpc_root_server_channel = grpc.insecure_channel(
            "localhost:" + grpc_root_server_port)
        self.grpc_channel = grpc.insecure_channel("localhost:" + grpc_port)

    def clean_up(self):
        self.grpc_channel.close()
        self.grpc_root_server_channel.close()
        stop_signal = signal.SIGINT
        self.backing_process.send_signal(stop_signal)
        backing_process_return_code = self.backing_process.wait()
        self.backing_process_logs.close()
        if backing_process_return_code not in [-stop_signal, 0]:
            logging.error("backing process %s stopped with code: %d" %
                          (self.label, backing_process_return_code))

        if self.serial_number:
            self.adb.remove_tcp_forward(self.grpc_port)
            self.adb.remove_tcp_forward(self.grpc_root_server_port)
            self.adb.reverse("--remove tcp:%d" % self.signal_port)
            self.adb.shell("logcat -d -f /data/misc/bluetooth/logs/system_log")
            self.adb.pull(
                "/data/misc/bluetooth/logs/btsnoop_hci.log %s" % os.path.join(
                    self.log_path_base, "%s_btsnoop_hci.log" % self.label))
            self.adb.pull(
                "/data/misc/bluetooth/logs/system_log %s" % os.path.join(
                    self.log_path_base, "%s_system_log" % self.label))

    def wait_channel_ready(self):
        future = grpc.channel_ready_future(self.grpc_channel)
        try:
            future.result(timeout=WAIT_CHANNEL_READY_TIMEOUT)
        except grpc.FutureTimeoutError:
            logging.error("wait channel ready timeout")

    def ensure_no_output(self, result):
        """
        Ensure a command has not output
        """
        asserts.assert_true(
            result is None or len(result) == 0,
            msg="command returned something when it shouldn't: %s" % result)

    def push_or_die(self, src_file_path, dst_file_path, push_timeout=300):
        """Pushes a file to the Android device

        Args:
            src_file_path: The path to the file to install.
            dst_file_path: The destination of the file.
            push_timeout: How long to wait for the push to finish in seconds
        """
        try:
            self.adb.ensure_root()
            self.ensure_verity_disabled()
            out = self.adb.push(
                '%s %s' % (src_file_path, dst_file_path), timeout=push_timeout)
            if 'error' in out:
                asserts.fail('Unable to push file %s to %s due to %s' %
                             (src_file_path, dst_file_path, out))
        except Exception as e:
            asserts.fail(
                msg='Unable to push file %s to %s due to %s' %
                (src_file_path, dst_file_path, e),
                extras=e)

    def tcp_forward_or_die(self, host_port, device_port):
        """
        Forward a TCP port from host to device or fail
        :param host_port: host port, int, 0 for adb to assign one
        :param device_port: device port, int
        :return: host port int
        """
        error_or_port = self.adb.tcp_forward(host_port, device_port)
        if not error_or_port:
            logging.debug("host port %d was already forwarded" % host_port)
            return host_port
        if not isinstance(error_or_port, int):
            asserts.fail(
                'Unable to forward host port %d to device port %d, error %s' %
                (host_port, device_port, error_or_port))
        return error_or_port

    def tcp_reverse_or_die(self, device_port, host_port):
        """
        Forward a TCP port from device to host or fail
        :param device_port: device port, int, 0 for adb to assign one
        :param host_port: host port, int
        :return: device port int
        """
        error_or_port = self.adb.reverse(
            "tcp:%d tcp:%d" % (device_port, host_port))
        if not error_or_port:
            logging.debug("device port %d was already reversed" % device_port)
            return device_port
        try:
            error_or_port = int(error_or_port)
        except ValueError:
            asserts.fail(
                'Unable to reverse device port %d to host port %d, error %s' %
                (device_port, host_port, error_or_port))
        return error_or_port

    def ensure_verity_disabled(self):
        """Ensures that verity is enabled.

        If verity is not enabled, this call will reboot the phone. Note that
        this only works on debuggable builds.
        """
        logging.debug("Disabling verity and remount for %s", self.serial_number)
        asserts.assert_true(self.adb.ensure_root(),
                            "device %s cannot run as root", self.serial_number)
        # The below properties will only exist if verity has been enabled.
        system_verity = self.adb.getprop('partition.system.verified')
        vendor_verity = self.adb.getprop('partition.vendor.verified')
        if system_verity or vendor_verity:
            self.adb.disable_verity()
            self.reboot()
        self.adb.remount()
        self.adb.wait_for_device(timeout=WAIT_FOR_DEVICE_TIMEOUT)

    def reboot(self, timeout_minutes=15.0):
        """Reboots the device.

        Reboot the device, wait for device to complete booting.
        """
        logging.debug("Rebooting %s", self.serial_number)
        self.adb.reboot()

        timeout_start = time.time()
        timeout = timeout_minutes * 60
        # Android sometimes return early after `adb reboot` is called. This
        # means subsequent calls may make it to the device before the reboot
        # goes through, return false positives for getprops such as
        # sys.boot_completed.
        while time.time() < timeout_start + timeout:
            try:
                self.adb.get_state()
                time.sleep(.1)
            except AdbError:
                # get_state will raise an error if the device is not found. We
                # want the device to be missing to prove the device has kicked
                # off the reboot.
                break
        minutes_left = timeout_minutes - (time.time() - timeout_start) / 60.0
        self.wait_for_boot_completion(timeout_minutes=minutes_left)

    def wait_for_boot_completion(self, timeout_minutes=15.0):
        """Waits for Android framework to broadcast ACTION_BOOT_COMPLETED.
        """
        timeout_start = time.time()
        timeout = timeout_minutes * 60

        self.adb.wait_for_device(timeout=WAIT_FOR_DEVICE_TIMEOUT)
        while time.time() < timeout_start + timeout:
            try:
                completed = self.adb.getprop("sys.boot_completed")
                if completed == '1':
                    return
            except AdbError:
                # adb shell calls may fail during certain period of booting
                # process, which is normal. Ignoring these errors.
                pass
            time.sleep(5)
        asserts.fail(msg='Device %s booting process timed out.' %
                     self.serial_number)
