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

from cert.event_stream import EventStream
from cert import rootservice_pb2_grpc as cert_rootservice_pb2_grpc
from hal.cert import api_pb2_grpc as hal_cert_pb2_grpc
from hci.cert import api_pb2_grpc as hci_cert_pb2_grpc
from l2cap.classic.cert import api_pb2_grpc as l2cap_cert_pb2_grpc

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
        devices.append(GdCertDevice(config["grpc_port"],
                                    config["grpc_root_server_port"],
                                    config["signal_port"],
                                    resolved_cmd, config["label"]))
    return devices

class GdCertDevice(GdDeviceBase):
    def __init__(self, grpc_port, grpc_root_server_port, signal_port, cmd, label):
        super().__init__(grpc_port, grpc_root_server_port, signal_port, cmd,
                         label, ACTS_CONTROLLER_CONFIG_NAME)

        # Cert stubs
        self.rootservice = cert_rootservice_pb2_grpc.RootCertStub(self.grpc_root_server_channel)
        self.hal = hal_cert_pb2_grpc.HciHalCertStub(self.grpc_channel)
        self.controller_read_only_property = cert_rootservice_pb2_grpc.ReadOnlyPropertyStub(self.grpc_channel)
        self.hci = hci_cert_pb2_grpc.AclManagerCertStub(self.grpc_channel)
        self.l2cap = l2cap_cert_pb2_grpc.L2capModuleCertStub(self.grpc_channel)

        # Event streams
        self.hal.hci_event_stream = EventStream(self.hal.FetchHciEvent)
        self.hal.hci_acl_stream = EventStream(self.hal.FetchHciAcl)
        self.hal.hci_sco_stream = EventStream(self.hal.FetchHciSco)
        self.hci.connection_complete_stream = EventStream(self.hci.FetchConnectionComplete)
        self.hci.disconnection_stream = EventStream(self.hci.FetchDisconnection)
        self.hci.connection_failed_stream = EventStream(self.hci.FetchConnectionFailed)
        self.hci.acl_stream = EventStream(self.hci.FetchAclData)
        self.l2cap.packet_stream = EventStream(self.l2cap.FetchL2capData)
        self.l2cap.connection_complete_stream = EventStream(self.l2cap.FetchConnectionComplete)
