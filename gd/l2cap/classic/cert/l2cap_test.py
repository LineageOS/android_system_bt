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

import time

from cert.gd_base_test_facade_only import GdFacadeOnlyBaseTestClass
from cert.event_asserts import EventAsserts
from cert.event_callback_stream import EventCallbackStream
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice
from google.protobuf import empty_pb2 as empty_proto
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from neighbor.facade import facade_pb2 as neighbor_facade
from hci.facade import acl_manager_facade_pb2 as acl_manager_facade
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import hci_packets, l2cap_packets


class L2capTest(GdFacadeOnlyBaseTestClass):

    def setup_test(self):
        self.device_under_test.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    'L2CAP'),))
        self.cert_device.rootservice.StartStack(
            facade_rootservice.StartStackRequest(
                module_under_test=facade_rootservice.BluetoothModule.Value(
                    'HCI_INTERFACES'),))

        self.device_under_test.wait_channel_ready()
        self.cert_device.wait_channel_ready()

        self.device_under_test.address = self.device_under_test.hci_controller.GetMacAddress(
            empty_proto.Empty()).address
        cert_address = self.cert_device.controller_read_only_property.ReadLocalAddress(
            empty_proto.Empty()).address
        self.cert_device.address = cert_address
        self.dut_address = common_pb2.BluetoothAddress(
            address=self.device_under_test.address)
        self.cert_address = common_pb2.BluetoothAddress(
            address=self.cert_device.address)

        self.device_under_test.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice.StopStackRequest())
        self.cert_device.rootservice.StopStack(
            facade_rootservice.StopStackRequest())

    def _setup_link_from_cert(self):

        self.device_under_test.neighbor.EnablePageScan(
            neighbor_facade.EnableMsg(enabled=True))

        with EventCallbackStream(
                self.cert_device.hci_acl_manager.CreateConnection(
                    acl_manager_facade.ConnectionMsg(
                        address_type=int(
                            hci_packets.AddressType.PUBLIC_DEVICE_ADDRESS),
                        address=bytes(self.dut_address.address)))
        ) as connection_event_stream:

            connection_event_asserts = EventAsserts(connection_event_stream)

            # Cert gets ConnectionComplete with a handle and sends ACL data
            handle = 0xfff

            def get_handle(packet):
                packet_bytes = packet.event
                if b'\x03\x0b\x00' in packet_bytes:
                    nonlocal handle
                    cc_view = hci_packets.ConnectionCompleteView(
                        hci_packets.EventPacketView(
                            bt_packets.PacketViewLittleEndian(
                                list(packet_bytes))))
                    handle = cc_view.GetConnectionHandle()
                    return True
                return False

            connection_event_asserts.assert_event_occurs(get_handle)

        return handle

    def _open_channel(
            self,
            cert_acl_data_stream,
            signal_id=1,
            cert_acl_handle=0x1,
            scid=0x0101,
            psm=0x33,
            mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC):
        cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)

        self.device_under_test.l2cap.SetDynamicChannel(
            l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                psm=psm, retransmission_mode=mode))
        open_channel = l2cap_packets.ConnectionRequestBuilder(
            signal_id, psm, scid)
        open_channel_l2cap = l2cap_packets.BasicFrameBuilder(1, open_channel)
        self.cert_device.hci_acl_manager.SendAclData(
            acl_manager_facade.AclData(
                handle=cert_acl_handle,
                payload=bytes(open_channel_l2cap.Serialize())))

        dcid = 0

        def verify_connection_response(packet):
            packet_bytes = packet.payload
            l2cap_view = l2cap_packets.BasicFrameView(
                bt_packets.PacketViewLittleEndian(list(packet_bytes)))
            l2cap_control_view = l2cap_packets.ControlView(
                l2cap_view.GetPayload())
            if l2cap_control_view.GetCode(
            ) != l2cap_packets.CommandCode.CONNECTION_RESPONSE:
                return False
            connection_response_view = l2cap_packets.ConnectionResponseView(
                l2cap_control_view)
            if connection_response_view.GetSourceCid(
            ) == scid and connection_response_view.GetResult(
            ) == l2cap_packets.ConnectionResponseResult.SUCCESS and connection_response_view.GetDestinationCid(
            ) != 0:
                nonlocal dcid
                dcid = connection_response_view.GetDestinationCid()
                return True
            return False

        cert_acl_data_asserts.assert_event_occurs(verify_connection_response)

        return dcid

    def test_connect(self):
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            self._open_channel(cert_acl_data_stream, 1, cert_acl_handle)

    def test_accept_disconnect(self):
        """
        L2CAP/COS/CED/BV-07-C
        """
        cert_acl_handle = self._setup_link_from_cert()

        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)

            scid = 0x41
            dcid = self._open_channel(cert_acl_data_stream, 1, cert_acl_handle,
                                      scid)

            close_channel = l2cap_packets.DisconnectionRequestBuilder(
                1, dcid, scid)
            close_channel_l2cap = l2cap_packets.BasicFrameBuilder(
                1, close_channel)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=cert_acl_handle,
                    payload=bytes(close_channel_l2cap.Serialize())))

            def verify_disconnection_response(packet):
                packet_bytes = packet.payload
                l2cap_view = l2cap_packets.BasicFrameView(
                    bt_packets.PacketViewLittleEndian(list(packet_bytes)))
                l2cap_control_view = l2cap_packets.ControlView(
                    l2cap_view.GetPayload())
                if l2cap_control_view.GetCode(
                ) != l2cap_packets.CommandCode.DISCONNECTION_RESPONSE:
                    return False
                disconnection_response_view = l2cap_packets.DisconnectionResponseView(
                    l2cap_control_view)
                return disconnection_response_view.GetSourceCid(
                ) == scid and disconnection_response_view.GetDestinationCid(
                ) == dcid

            cert_acl_data_asserts.assert_event_occurs(
                verify_disconnection_response)
