#!/usr/bin/env python3
#
#   Copyright 2020 - The Android Open Source Project
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

from cert.closable import Closable
from cert.closable import safeClose
from cert.py_acl_manager import PyAclManager
from cert.truth import assertThat
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import l2cap_packets
from bluetooth_packets_python3.l2cap_packets import CommandCode
from cert.event_stream import FilteringEventStream
from cert.event_stream import IEventStream
from cert.matchers import L2capMatchers


class CertL2capChannel(IEventStream):

    def __init__(self, device, scid, acl_stream):
        self._device = device
        self._scid = scid
        self._our_acl_view = acl_stream

    def get_event_queue(self):
        return self._our_acl_view.get_event_queue()


class CertL2cap(Closable):

    def __init__(self, device):
        self._device = device
        self._acl_manager = PyAclManager(device)
        self._acl = None

        self.control_table = {
            CommandCode.CONNECTION_REQUEST:
            self._on_connection_request_default,
            CommandCode.CONNECTION_RESPONSE:
            self._on_connection_response_default,
            CommandCode.CONFIGURATION_REQUEST:
            self._on_configuration_request_default,
            CommandCode.CONFIGURATION_RESPONSE:
            self._on_configuration_response_default,
            CommandCode.DISCONNECTION_REQUEST:
            self._on_disconnection_request_default,
            CommandCode.DISCONNECTION_RESPONSE:
            self._on_disconnection_response_default,
            CommandCode.INFORMATION_REQUEST:
            self._on_information_request_default,
            CommandCode.INFORMATION_RESPONSE:
            self._on_information_response_default
        }

        self.scid_to_dcid = {}
        self.ertm_tx_window_size = 10
        self.ertm_max_transmit = 20

    def close(self):
        self._acl_manager.close()
        safeClose(self._acl)

    def connect_acl(self, remote_addr):
        self._acl = self._acl_manager.initiate_connection(remote_addr)
        self._acl.wait_for_connection_complete()
        self.get_acl_stream().register_callback(self._handle_control_packet)

    def open_channel(self, signal_id, psm, scid):
        # what is the 1 here for?
        open_channel = l2cap_packets.BasicFrameBuilder(
            1, l2cap_packets.ConnectionRequestBuilder(signal_id, psm, scid))
        self.send_acl(open_channel)

        assertThat(self._acl).emits(L2capMatchers.ConnectionResponse(scid))
        return CertL2capChannel(self._device, scid, self.get_acl_stream())

    # prefer to use channel abstraction instead, if at all possible
    def send_acl(self, packet):
        self._acl.send(packet.Serialize())

    # temporary until clients migrated
    def get_acl_stream(self):
        return self._acl_manager.get_acl_stream()

    # temporary until clients migrated
    def get_acl(self):
        return self._acl

    # temporary until clients migrated
    def get_dcid(self, scid):
        return self.scid_to_dcid[scid]

    # more of a hack for the moment
    def turn_on_ertm(self, tx_window_size=10, max_transmit=20):
        self.ertm_tx_window_size = tx_window_size
        self.ertm_max_transmit = max_transmit
        self.control_table[
            CommandCode.
            CONNECTION_RESPONSE] = self._on_connection_response_use_ertm

    # more of a hack for the moment
    def turn_on_ertm_and_fcs(self):
        self.control_table[
            CommandCode.
            CONNECTION_RESPONSE] = self._on_connection_response_use_ertm_and_fcs

    # more of a hack for the moment
    def ignore_config_and_connections(self):
        self.control_table[CommandCode.CONFIGURATION_REQUEST] = lambda _: True
        self.control_table[CommandCode.CONNECTION_RESPONSE] = lambda _: True

    # more of a hack for the moment
    def reply_with_unacceptable_parameters(self):
        self.control_table[
            CommandCode.
            CONFIGURATION_REQUEST] = self._on_configuration_request_unacceptable_parameters

    # more of a hack for the moment
    def reply_with_unknown_options_and_hint(self):
        self.control_table[
            CommandCode.
            CONNECTION_RESPONSE] = self._on_connection_response_configuration_request_with_unknown_options_and_hint

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
        self.send_acl(connection_response_l2cap)
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
        self.send_acl(config_request_l2cap)
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
        ertm_option.tx_window_size = self.ertm_tx_window_size
        ertm_option.max_transmit = self.ertm_max_transmit
        ertm_option.retransmission_time_out = 2000
        ertm_option.monitor_time_out = 12000
        ertm_option.maximum_pdu_size = 1010

        options = [ertm_option]

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.END, options)

        config_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_request)

        self.send_acl(config_request_l2cap)
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
        ertm_option.tx_window_size = self.ertm_tx_window_size
        ertm_option.max_transmit = self.ertm_max_transmit
        ertm_option.retransmission_time_out = 2000
        ertm_option.monitor_time_out = 12000
        ertm_option.maximum_pdu_size = 1010

        fcs_option = l2cap_packets.FrameCheckSequenceOption()
        fcs_option.fcs_type = l2cap_packets.FcsType.DEFAULT

        options = [ertm_option, fcs_option]

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.END, options)

        config_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_request)

        self.send_acl(config_request_l2cap)
        return True

    def _on_connection_response_configuration_request_with_unknown_options_and_hint(
            self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = 0x1234
        mtu_opt.is_hint = l2cap_packets.ConfigurationOptionIsHint.OPTION_IS_A_HINT

        options = [mtu_opt]
        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.END, options)
        config_request_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_request)

        byte_array = bytearray(config_request_l2cap.Serialize())
        ## Modify configuration option type to be a unknown
        byte_array[12] |= 0x7f
        self._acl.send(bytes(byte_array))
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
        self.send_acl(config_response_l2cap)

    def _on_configuration_request_unacceptable_parameters(
            self, l2cap_control_view):
        configuration_request = l2cap_packets.ConfigurationRequestView(
            l2cap_control_view)
        sid = configuration_request.GetIdentifier()
        dcid = configuration_request.GetDestinationCid()

        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = 123
        fcs_opt = l2cap_packets.FrameCheckSequenceOption()
        fcs_opt.fcs_type = l2cap_packets.FcsType.DEFAULT
        rfc_opt = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        rfc_opt.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.L2CAP_BASIC

        config_response = l2cap_packets.ConfigurationResponseBuilder(
            sid, self.scid_to_dcid.get(dcid, 0), l2cap_packets.Continuation.END,
            l2cap_packets.ConfigurationResponseResult.UNACCEPTABLE_PARAMETERS,
            [mtu_opt, fcs_opt, rfc_opt])
        config_response_l2cap = l2cap_packets.BasicFrameBuilder(
            1, config_response)
        self.send_acl(config_response_l2cap)

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
        self.send_acl(disconnection_response_l2cap)

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
            self.send_acl(response_l2cap)
            return
        if information_type == l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
            response = l2cap_packets.InformationResponseExtendedFeaturesBuilder(
                sid, l2cap_packets.InformationRequestResult.SUCCESS, 0, 0, 0, 1,
                0, 1, 0, 0, 0, 0)
            response_l2cap = l2cap_packets.BasicFrameBuilder(1, response)
            self.send_acl(response_l2cap)
            return
        if information_type == l2cap_packets.InformationRequestInfoType.FIXED_CHANNELS_SUPPORTED:
            response = l2cap_packets.InformationResponseFixedChannelsBuilder(
                sid, l2cap_packets.InformationRequestResult.SUCCESS, 2)
            response_l2cap = l2cap_packets.BasicFrameBuilder(1, response)
            self.send_acl(response_l2cap)
            return

    def _on_information_response_default(self, l2cap_control_view):
        information_response = l2cap_packets.InformationResponseView(
            l2cap_control_view)

    def _handle_control_packet(self, l2cap_packet):
        packet_bytes = l2cap_packet.payload
        l2cap_view = l2cap_packets.BasicFrameView(
            bt_packets.PacketViewLittleEndian(list(packet_bytes)))
        if l2cap_view.GetChannelId() != 1:
            return
        l2cap_control_view = l2cap_packets.ControlView(l2cap_view.GetPayload())
        fn = self.control_table.get(l2cap_control_view.GetCode())
        if fn is not None:
            fn(l2cap_control_view)
        return
