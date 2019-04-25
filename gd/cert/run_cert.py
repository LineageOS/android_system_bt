#!/usr/bin/env python3
#
# Copyright 2019, The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import signal
import sys
import subprocess
import os
import argparse

ANDROID_BUILD_TOP = os.environ.get('ANDROID_BUILD_TOP')

if ANDROID_BUILD_TOP is None:
    print("Please lunch a target first")
    sys.exit(1)

HOST_OUT = os.environ.get('ANDROID_HOST_OUT')

BUILD_TARGETS = [
    "root-canal",
    "stack_with_facade",
    "bluetooth_cert_test",
]

SOONG_UI_BASH = "build/soong/soong_ui.bash"
ROOTCANAL = HOST_OUT + "/nativetest64/root-canal/root-canal"
STACK_WITH_FACADE = HOST_OUT + "/bin/stack_with_facade"
TEST_SUITE = HOST_OUT + "/nativetest64/bluetooth_cert_test/bluetooth_cert_test"


def _build(num_tasks):
    build_cmd = [SOONG_UI_BASH, "--make-mode"] + BUILD_TARGETS + [
        "-j" + str(num_tasks)]
    print(build_cmd)
    p = subprocess.call(build_cmd, cwd=ANDROID_BUILD_TOP, env=os.environ.copy())
    if p != 0:
        print('BUILD FAILED, return code: {0}'.format(str(p)))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Run cert tests.')
    parser.add_argument(
        '--skip-make',
        type=bool,
        nargs='?',
        dest='skip_make',
        const=-1,
        default=False,
        help='skip building and run test immediately')
    parser.add_argument(
        '-j',
        type=int,
        nargs='?',
        dest='num_tasks',
        const=-1,
        default=40,
        help='Number of tasks to run at the same time')
    parser.add_argument(
        '--rootcanal_test_port',
        nargs='?',
        dest='rootcanal_test_port',
        const=-1,
        default="6401",
        help='Rootcanal test channel port')
    parser.add_argument(
        '--rootcanal_hci_port',
        nargs='?',
        dest='rootcanal_hci_port',
        const=-1,
        default="6402",
        help='Rootcanal HCI channel port')
    parser.add_argument(
        '--rootcanal_link_layer_port',
        nargs='?',
        dest='rootcanal_link_layer_port',
        const=-1,
        default="6403",
        help='Rootcanal Link Layer device channel port')
    parser.add_argument(
        '--grpc_port',
        nargs='?',
        dest='grpc_port',
        const=-1,
        default="8899",
        help='gRPC port')
    args = parser.parse_args()
    if not args.skip_make:
        _build(args.num_tasks)
    rootcanal_args = [ROOTCANAL,
                      args.rootcanal_test_port,
                      args.rootcanal_hci_port,
                      args.rootcanal_link_layer_port]
    p_rootcanal = subprocess.Popen(rootcanal_args,
                                   cwd=ANDROID_BUILD_TOP,
                                   env=os.environ.copy())
    stack_with_facade_args = [STACK_WITH_FACADE,
                              "--port=" + args.grpc_port,
                              "--rootcanal-port=" + args.rootcanal_hci_port]
    p_stack_with_facade = subprocess.Popen(stack_with_facade_args,
                                           cwd=ANDROID_BUILD_TOP,
                                           env=os.environ.copy())
    p_test_suite = subprocess.Popen(TEST_SUITE, cwd=ANDROID_BUILD_TOP,
                                    env=os.environ.copy())
    p_test_suite.wait()
    p_stack_with_facade.send_signal(signal.SIGINT)
    p_stack_with_facade.wait()
    p_rootcanal.send_signal(signal.SIGINT)
    p_rootcanal.wait()


if __name__ == '__main__':
    main()
