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

from gd_device_base import GdDeviceBase
from gd_device_base import replace_vars

from cert import rootservice_pb2_grpc as cert_rootservice_pb2_grpc
from hal.cert import api_pb2_grpc as hal_cert_pb2_grpc

ACTS_CONTROLLER_CONFIG_NAME = "GdCertDevice"
ACTS_CONTROLLER_REFERENCE_NAME = "gd_cert_devices"

def create(configs):
    if not configs:
        raise GdDeviceConfigError("Configuration is empty")
    elif not isinstance(configs, list):
        raise GdDeviceConfigError("Configuration should be a list")
    return get_instances_with_configs(configs)


def destroy(devices):
    for device in devices:
        try:
            device.clean_up()
        except:
            device.log.exception("Failed to clean up properly.")


def get_info(devices):
    return []


def get_instances_with_configs(configs):
    print(configs)
    devices = []
    for config in configs:
        resolved_cmd = []
        for entry in config["cmd"]:
            resolved_cmd.append(replace_vars(entry, config))
        devices.append(GdCertDevice(config["grpc_port"], config["grpc_root_server_port"], resolved_cmd, config["label"]))
    return devices

class GdCertDevice(GdDeviceBase):
    def __init__(self, grpc_port, grpc_root_server_port, cmd, label):
        super().__init__(grpc_port, grpc_root_server_port, cmd, label, ACTS_CONTROLLER_CONFIG_NAME)
        self.rootservice = cert_rootservice_pb2_grpc.RootCertStub(self.grpc_root_server_channel)
        self.hal = hal_cert_pb2_grpc.HciHalCertStub(self.grpc_channel)

