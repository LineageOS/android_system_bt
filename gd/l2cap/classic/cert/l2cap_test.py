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

        self.cert_acl_handle = 0

        self.on_connection_request = None
        self.on_connection_response = None
        self.on_configuration_request = None
        self.on_configuration_response = None
        self.on_disconnection_request = None
        self.on_disconnection_response = None
        self.on_information_request = None
        self.on_information_response = None

        self.scid_to_dcid = {}

    def _on_connection_request_default(self, l2cap_control_view):
        connection_request_view = l2cap_packets.ConnectionRequestView(
            l2cap_control_view)
        sid = connection_request_view.GetIdentifier()
        cid = connection_request_view.GetSourceCid()

        self.scid_to_dcid[cid] = cid

        connection_response = l2cap_packets.ConnectionResponseBuilder(
            sid, cid, cid, l2cap_packets.ConnectionResponseResult.SUCCESS,
            l2cap_packets.ConnectionResponseStatus.
            NO_FURTHER_INFORMATION_AVAILABLE)
        connection_response_l2cap = l2cap_packets.BasicFrameBuilder(
            1, connection_response)
        self.cert_device.hci_acl_manager.SendAclData(
            acl_manager_facade.AclData(
                handle=self.cert_acl_handle,
                payload=bytes(connection_response_l2cap.Serialize())))
        return True

    def _on_connection_response_default(self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.END, [])
        config_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_request)
        self.cert_device.hci_acl_manager.SendAclData(
            acl_manager_facade.AclData(
                handle=self.cert_acl_handle,
                payload=bytes(config_request_l2cap.Serialize())))
        return True

    def _on_connection_response_use_ertm(self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

        # FIXME: This doesn't work!
        ertm_option = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        ertm_option.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.L2CAP_BASIC
        ertm_option.tx_window_size = 20
        ertm_option.max_transmit = 20
        ertm_option.retransmission_time_out = 2000
        ertm_option.monitor_time_out = 12000
        ertm_option.maximum_pdu_size = 1010

        options = [ertm_option]

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.END, options)

        config_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_request)

        config_packet = bytearray([
            0x1a,
            0x00,
            0x01,
            0x00,
            0x04,
            sid + 1,
            0x16,
            0x00,
            dcid & 0xff,
            dcid >> 8,
            0x00,
            0x00,
            0x01,
            0x02,
            0xa0,
            0x02,  # MTU
            0x04,
            0x09,
            0x03,
            0x0a,
            0x14,
            0xd0,
            0x07,
            0xe0,
            0x2e,
            0xf2,
            0x03,  # ERTM
            0x05,
            0x01,
            0x00  # FCS
        ])

        self.cert_device.hci_acl_manager.SendAclData(
            acl_manager_facade.AclData(
                handle=self.cert_acl_handle, payload=bytes(config_packet)))
        return True

    def _on_connection_response_use_ertm_and_fcs(self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

        # FIXME: This doesn't work!
        ertm_option = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        ertm_option.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.L2CAP_BASIC
        ertm_option.tx_window_size = 20
        ertm_option.max_transmit = 20
        ertm_option.retransmission_time_out = 2000
        ertm_option.monitor_time_out = 12000
        ertm_option.maximum_pdu_size = 1010

        options = [ertm_option]

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.END, options)

        config_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_request)

        config_packet = bytearray([
            0x1a,
            0x00,
            0x01,
            0x00,
            0x04,
            sid + 1,
            0x16,
            0x00,
            dcid & 0xff,
            dcid >> 8,
            0x00,
            0x00,
            0x01,
            0x02,
            0xa0,
            0x02,  # MTU
            0x04,
            0x09,
            0x03,
            0x0a,
            0x14,
            0xd0,
            0x07,
            0xe0,
            0x2e,
            0xf2,
            0x03,  # ERTM
            0x05,
            0x01,
            0x01  # FCS
        ])

        self.cert_device.hci_acl_manager.SendAclData(
            acl_manager_facade.AclData(
                handle=self.cert_acl_handle, payload=bytes(config_packet)))
        return True

    def _on_configuration_request_default(self, l2cap_control_view):
        configuration_request = l2cap_packets.ConfigurationRequestView(
            l2cap_control_view)
        sid = configuration_request.GetIdentifier()
        dcid = configuration_request.GetDestinationCid()
        config_response = l2cap_packets.ConfigurationResponseBuilder(
            sid, self.scid_to_dcid.get(dcid, 0), l2cap_packets.Continuation.END,
            l2cap_packets.ConfigurationResponseResult.SUCCESS, [])
        config_response_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_response)
        self.cert_device.hci_acl_manager.SendAclData(
            acl_manager_facade.AclData(
                handle=self.cert_acl_handle,
                payload=bytes(config_response_l2cap.Serialize())))

    def _on_configuration_response_default(self, l2cap_control_view):
        configuration_response = l2cap_packets.ConfigurationResponseView(
            l2cap_control_view)
        sid = configuration_response.GetIdentifier()

    def _on_disconnection_request_default(self, l2cap_control_view):
        disconnection_request = l2cap_packets.DisconnectionRequestView(
            l2cap_control_view)
        sid = disconnection_request.GetIdentifier()
        scid = disconnection_request.GetSourceCid()
        dcid = disconnection_request.GetDestinationCid()
        disconnection_response = l2cap_packets.DisconnectionResponseBuilder(
            sid, dcid, scid)
        disconnection_response_l2cap = l2cap_packets.BasicFrameBuilder(
            1, disconnection_response)
        self.cert_device.hci_acl_manager.SendAclData(
            acl_manager_facade.AclData(
                handle=self.cert_acl_handle,
                payload=bytes(disconnection_response_l2cap.Serialize())))

    def _on_disconnection_response_default(self, l2cap_control_view):
        disconnection_response = l2cap_packets.DisconnectionResponseView(
            l2cap_control_view)

    def _on_information_request_default(self, l2cap_control_view):
        information_request = l2cap_packets.InformationRequestView(
            l2cap_control_view)
        sid = information_request.GetIdentifier()
        information_type = information_request.GetInfoType()
        if information_type == l2cap_packets.InformationRequestInfoType.CONNECTIONLESS_MTU:
            response = l2cap_packets.InformationResponseConnectionlessMtuBuilder(
                sid, l2cap_packets.InformationRequestResult.SUCCESS, 100)
            response_l2cap = l2cap_packets.BasicFrameBuilder(1, response)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=self.cert_acl_handle,
                    payload=bytes(response_l2cap.Serialize())))
            return
        if information_type == l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
            response = l2cap_packets.InformationResponseExtendedFeaturesBuilder(
                sid, l2cap_packets.InformationRequestResult.SUCCESS, 0, 0, 0, 1,
                0, 1, 0, 0, 0, 0)
            response_l2cap = l2cap_packets.BasicFrameBuilder(1, response)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=self.cert_acl_handle,
                    payload=bytes(response_l2cap.Serialize())))
            return
        if information_type == l2cap_packets.InformationRequestInfoType.FIXED_CHANNELS_SUPPORTED:
            response = l2cap_packets.InformationResponseFixedChannelsBuilder(
                sid, l2cap_packets.InformationRequestResult.SUCCESS, 2)
            response_l2cap = l2cap_packets.BasicFrameBuilder(1, response)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=self.cert_acl_handle,
                    payload=bytes(response_l2cap.Serialize())))
            return

    def _on_information_response_default(self, l2cap_control_view):
        information_response = l2cap_packets.InformationResponseView(
            l2cap_control_view)

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice.StopStackRequest())
        self.cert_device.rootservice.StopStack(
            facade_rootservice.StopStackRequest())

    def _handle_control_packet(self, l2cap_packet):
        packet_bytes = l2cap_packet.payload
        l2cap_view = l2cap_packets.BasicFrameView(
            bt_packets.PacketViewLittleEndian(list(packet_bytes)))
        if l2cap_view.GetChannelId() != 1:
            return
        l2cap_control_view = l2cap_packets.ControlView(l2cap_view.GetPayload())
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.CONNECTION_REQUEST:
            return self.on_connection_request(
                l2cap_control_view
            ) if self.on_connection_request else self._on_connection_request_default(
                l2cap_control_view)
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.CONNECTION_RESPONSE:
            return self.on_connection_response(
                l2cap_control_view
            ) if self.on_connection_response else self._on_connection_response_default(
                l2cap_control_view)
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.CONFIGURATION_REQUEST:
            return self.on_configuration_request(
                l2cap_control_view
            ) if self.on_configuration_request else self._on_configuration_request_default(
                l2cap_control_view)
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.CONFIGURATION_RESPONSE:
            return self.on_configuration_response(
                l2cap_control_view
            ) if self.on_configuration_response else self._on_configuration_response_default(
                l2cap_control_view)
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.DISCONNECTION_REQUEST:
            return self.on_disconnection_request(
                l2cap_control_view
            ) if self.on_disconnection_request else self._on_disconnection_request_default(
                l2cap_control_view)
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.DISCONNECTION_RESPONSE:
            return self.on_disconnection_response(
                l2cap_control_view
            ) if self.on_disconnection_response else self._on_disconnection_response_default(
                l2cap_control_view)
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.INFORMATION_REQUEST:
            return self.on_information_request(
                l2cap_control_view
            ) if self.on_information_request else self._on_information_request_default(
                l2cap_control_view)
        if l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.INFORMATION_RESPONSE:
            return self.on_information_response(
                l2cap_control_view
            ) if self.on_information_response else self._on_information_response_default(
                l2cap_control_view)

    def is_correct_configuration_response(self, l2cap_packet):
        packet_bytes = l2cap_packet.payload
        l2cap_view = l2cap_packets.BasicFrameView(
            bt_packets.PacketViewLittleEndian(list(packet_bytes)))
        if l2cap_view.GetChannelId() != 1:
            return False
        l2cap_control_view = l2cap_packets.ControlView(l2cap_view.GetPayload())
        if l2cap_control_view.GetCode(
        ) != l2cap_packets.CommandCode.CONFIGURATION_RESPONSE:
            return False
        configuration_response_view = l2cap_packets.ConfigurationResponseView(
            l2cap_control_view)
        return configuration_response_view.GetResult(
        ) == l2cap_packets.ConfigurationResponseResult.SUCCESS

    def is_correct_configuration_request(self, l2cap_packet):
        packet_bytes = l2cap_packet.payload
        l2cap_view = l2cap_packets.BasicFrameView(
            bt_packets.PacketViewLittleEndian(list(packet_bytes)))
        if l2cap_view.GetChannelId() != 1:
            return False
        l2cap_control_view = l2cap_packets.ControlView(l2cap_view.GetPayload())
        return l2cap_control_view.GetCode(
        ) == l2cap_packets.CommandCode.CONFIGURATION_REQUEST

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

        self.cert_acl_handle = handle
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
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            scid = 0x41
            psm = 0x33
            dcid = self._open_channel(cert_acl_data_stream, 1, cert_acl_handle,
                                      scid, psm)

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

    def test_disconnect_on_timeout(self):
        """
        L2CAP/COS/CED/BV-08-C
        """
        cert_acl_handle = self._setup_link_from_cert()

        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            scid = 0x41
            psm = 0x33
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            # Don't send configuration request or response back
            self.on_configuration_request = lambda _: True
            self.on_connection_response = lambda _: True

            dcid = self._open_channel(cert_acl_data_stream, 1, cert_acl_handle,
                                      scid, psm)

            def is_configuration_response(l2cap_packet):
                packet_bytes = l2cap_packet.payload
                l2cap_view = l2cap_packets.BasicFrameView(
                    bt_packets.PacketViewLittleEndian(list(packet_bytes)))
                if l2cap_view.GetChannelId() != 1:
                    return False
                l2cap_control_view = l2cap_packets.ControlView(
                    l2cap_view.GetPayload())
                return l2cap_control_view.GetCode(
                ) == l2cap_packets.CommandCode.CONFIGURATION_RESPONSE

            cert_acl_data_asserts.assert_none_matching(
                is_configuration_response)

    def test_respond_to_echo_request(self):
        """
        L2CAP/COS/ECH/BV-01-C [Respond to Echo Request]
        Verify that the IUT responds to an echo request.
        """
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            echo_request = l2cap_packets.EchoRequestBuilder(
                100, l2cap_packets.DisconnectionRequestBuilder(1, 2, 3))
            echo_request_l2cap = l2cap_packets.BasicFrameBuilder(
                1, echo_request)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=cert_acl_handle,
                    payload=bytes(echo_request_l2cap.Serialize())))

            cert_acl_data_asserts.assert_event_occurs(
                lambda packet: b"\x06\x01\x04\x00\x02\x00\x03\x00" in packet.payload
            )

    def test_reject_unknown_command(self):
        """
        L2CAP/COS/CED/BI-01-C
        """
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            invalid_command_packet = b"\x04\x00\x01\x00\xff\x01\x00\x00"
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=cert_acl_handle,
                    payload=bytes(invalid_command_packet)))

            def is_command_reject(l2cap_packet):
                packet_bytes = l2cap_packet.payload
                l2cap_view = l2cap_packets.BasicFrameView(
                    bt_packets.PacketViewLittleEndian(list(packet_bytes)))
                if l2cap_view.GetChannelId() != 1:
                    return False
                l2cap_control_view = l2cap_packets.ControlView(
                    l2cap_view.GetPayload())
                return l2cap_control_view.GetCode(
                ) == l2cap_packets.CommandCode.COMMAND_REJECT

            cert_acl_data_asserts.assert_event_occurs(is_command_reject)

    def test_query_for_1_2_features(self):
        """
        L2CAP/COS/IEX/BV-01-C [Query for 1.2 Features]
        """
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)
            signal_id = 3
            information_request = l2cap_packets.InformationRequestBuilder(
                signal_id, l2cap_packets.InformationRequestInfoType.
                FIXED_CHANNELS_SUPPORTED)
            echo_request_l2cap = l2cap_packets.BasicFrameBuilder(
                1, information_request)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=cert_acl_handle,
                    payload=bytes(echo_request_l2cap.Serialize())))

            def is_correct_information_response(l2cap_packet):
                packet_bytes = l2cap_packet.payload
                l2cap_view = l2cap_packets.BasicFrameView(
                    bt_packets.PacketViewLittleEndian(list(packet_bytes)))
                if l2cap_view.GetChannelId() != 1:
                    return False
                l2cap_control_view = l2cap_packets.ControlView(
                    l2cap_view.GetPayload())
                if l2cap_control_view.GetCode(
                ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                    return False
                information_response_view = l2cap_packets.InformationResponseView(
                    l2cap_control_view)
                return information_response_view.GetInfoType(
                ) == l2cap_packets.InformationRequestInfoType.FIXED_CHANNELS_SUPPORTED

            cert_acl_data_asserts.assert_event_occurs(
                is_correct_information_response)

    def test_extended_feature_info_response_ertm(self):
        """
        L2CAP/EXF/BV-01-C [Extended Features Information Response for Enhanced
        Retransmission Mode]
        """
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            signal_id = 3
            information_request = l2cap_packets.InformationRequestBuilder(
                signal_id, l2cap_packets.InformationRequestInfoType.
                EXTENDED_FEATURES_SUPPORTED)
            echo_request_l2cap = l2cap_packets.BasicFrameBuilder(
                1, information_request)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=cert_acl_handle,
                    payload=bytes(echo_request_l2cap.Serialize())))

            def is_correct_information_response(l2cap_packet):
                packet_bytes = l2cap_packet.payload
                l2cap_view = l2cap_packets.BasicFrameView(
                    bt_packets.PacketViewLittleEndian(list(packet_bytes)))
                if l2cap_view.GetChannelId() != 1:
                    return False
                l2cap_control_view = l2cap_packets.ControlView(
                    l2cap_view.GetPayload())
                if l2cap_control_view.GetCode(
                ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                    return False
                information_response_view = l2cap_packets.InformationResponseView(
                    l2cap_control_view)
                if information_response_view.GetInfoType(
                ) != l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
                    return False
                extended_features_view = l2cap_packets.InformationResponseExtendedFeaturesView(
                    information_response_view)
                return extended_features_view.GetEnhancedRetransmissionMode()

            cert_acl_data_asserts.assert_event_occurs(
                is_correct_information_response)

    def test_extended_feature_info_response_fcs(self):
        """
        L2CAP/EXF/BV-03-C [Extended Features Information Response for FCS Option]
        Note: This is not mandated by L2CAP Spec
        """
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            signal_id = 3
            information_request = l2cap_packets.InformationRequestBuilder(
                signal_id, l2cap_packets.InformationRequestInfoType.
                EXTENDED_FEATURES_SUPPORTED)
            echo_request_l2cap = l2cap_packets.BasicFrameBuilder(
                1, information_request)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=cert_acl_handle,
                    payload=bytes(echo_request_l2cap.Serialize())))

            def is_correct_information_response(l2cap_packet):
                packet_bytes = l2cap_packet.payload
                l2cap_view = l2cap_packets.BasicFrameView(
                    bt_packets.PacketViewLittleEndian(list(packet_bytes)))
                if l2cap_view.GetChannelId() != 1:
                    return False
                l2cap_control_view = l2cap_packets.ControlView(
                    l2cap_view.GetPayload())
                if l2cap_control_view.GetCode(
                ) != l2cap_packets.CommandCode.INFORMATION_RESPONSE:
                    return False
                information_response_view = l2cap_packets.InformationResponseView(
                    l2cap_control_view)
                if information_response_view.GetInfoType(
                ) != l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
                    return False
                extended_features_view = l2cap_packets.InformationResponseExtendedFeaturesView(
                    information_response_view)
                return extended_features_view.GetFcsOption()

            cert_acl_data_asserts.assert_event_occurs(
                is_correct_information_response)

    def test_config_channel_not_use_FCS(self):
        """
        L2CAP/FOC/BV-01-C [IUT Initiated Configuration of the FCS Option]
        Verify the IUT can configure a channel to not use FCS in I/S-frames.
        """
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            self.on_connection_response = self._on_connection_response_use_ertm

            psm = 0x33
            scid = 0x41
            dcid = self._open_channel(
                cert_acl_data_stream,
                1,
                cert_acl_handle,
                scid,
                psm,
                mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)
            # FIXME: Order shouldn't matter here
            cert_acl_data_asserts.assert_event_occurs(
                self.is_correct_configuration_response)
            cert_acl_data_asserts.assert_event_occurs(
                self.is_correct_configuration_request)

            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            cert_acl_data_asserts.assert_event_occurs(
                lambda packet: b"abc" in packet.payload)

    def test_explicitly_request_use_FCS(self):
        """
        L2CAP/FOC/BV-02-C [Lower Tester Explicitly Requests FCS should be Used]
        Verify the IUT will include the FCS in I/S-frames if the Lower Tester explicitly requests that FCS
        should be used.
        """

        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            self.on_connection_response = self._on_connection_response_use_ertm_and_fcs
            psm = 0x33
            scid = 0x41
            dcid = self._open_channel(
                cert_acl_data_stream,
                1,
                cert_acl_handle,
                scid,
                psm,
                mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)
            # FIXME: Order shouldn't matter here
            cert_acl_data_asserts.assert_event_occurs(
                self.is_correct_configuration_response)
            cert_acl_data_asserts.assert_event_occurs(
                self.is_correct_configuration_request)

            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            cert_acl_data_asserts.assert_event_occurs(
                lambda packet: b"abc\x4f\xa3" in packet.payload
            )  # TODO: Use packet parser

    def test_transmit_i_frames(self):
        """
        L2CAP/ERM/BV-01-C [Transmit I-frames]
        """
        cert_acl_handle = self._setup_link_from_cert()
        with EventCallbackStream(
                self.cert_device.hci_acl_manager.FetchAclData(
                    empty_proto.Empty())) as cert_acl_data_stream:
            cert_acl_data_asserts = EventAsserts(cert_acl_data_stream)
            cert_acl_data_stream.register_callback(self._handle_control_packet)

            self.on_connection_response = self._on_connection_response_use_ertm
            psm = 0x33
            scid = 0x41
            dcid = self._open_channel(
                cert_acl_data_stream,
                1,
                cert_acl_handle,
                scid,
                psm,
                mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM)

            # FIXME: Order shouldn't matter here
            cert_acl_data_asserts.assert_event_occurs(
                self.is_correct_configuration_response)
            cert_acl_data_asserts.assert_event_occurs(
                self.is_correct_configuration_request)

            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            cert_acl_data_asserts.assert_event_occurs(
                lambda packet: b"abc" in packet.payload)

            # Assemble a sample packet. TODO: Use RawBuilder
            sample_packet = l2cap_packets.CommandRejectNotUnderstoodBuilder(1)

            i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
                dcid, 0, l2cap_packets.Final.NOT_SET, 1,
                l2cap_packets.SegmentationAndReassembly.UNSEGMENTED,
                sample_packet)
            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=self.cert_acl_handle,
                    payload=bytes(i_frame.Serialize())))

            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            cert_acl_data_asserts.assert_event_occurs(
                lambda packet: b"abc" in packet.payload)

            i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
                dcid, 1, l2cap_packets.Final.NOT_SET, 2,
                l2cap_packets.SegmentationAndReassembly.UNSEGMENTED,
                sample_packet)

            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=self.cert_acl_handle,
                    payload=bytes(i_frame.Serialize())))

            self.device_under_test.l2cap.SendDynamicChannelPacket(
                l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'))
            cert_acl_data_asserts.assert_event_occurs(
                lambda packet: b"abc" in packet.payload)

            i_frame = l2cap_packets.EnhancedInformationFrameBuilder(
                dcid, 2, l2cap_packets.Final.NOT_SET, 3,
                l2cap_packets.SegmentationAndReassembly.UNSEGMENTED,
                sample_packet)

            self.cert_device.hci_acl_manager.SendAclData(
                acl_manager_facade.AclData(
                    handle=self.cert_acl_handle,
                    payload=bytes(i_frame.Serialize())))
