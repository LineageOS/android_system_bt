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
from bluetooth_packets_python3.l2cap_packets import Final
from bluetooth_packets_python3.l2cap_packets import SegmentationAndReassembly
from bluetooth_packets_python3.l2cap_packets import SupervisoryFunction
from bluetooth_packets_python3.l2cap_packets import Poll
from bluetooth_packets_python3.l2cap_packets import InformationRequestInfoType
from cert.event_stream import FilteringEventStream
from cert.event_stream import IEventStream
from cert.matchers import L2capMatchers
from cert.captures import L2capCaptures


class CertL2capChannel(IEventStream):

    def __init__(self, device, scid, dcid, acl_stream, acl, control_channel):
        self._device = device
        self._scid = scid
        self._dcid = dcid
        self._acl_stream = acl_stream
        self._acl = acl
        self._control_channel = control_channel
        self._our_acl_view = FilteringEventStream(
            acl_stream, L2capMatchers.ExtractBasicFrame(scid))

    def get_event_queue(self):
        return self._our_acl_view.get_event_queue()

    def send(self, packet):
        frame = l2cap_packets.BasicFrameBuilder(self._dcid, packet)
        self._acl.send(frame.Serialize())

    def send_i_frame(self,
                     tx_seq,
                     req_seq,
                     f=Final.NOT_SET,
                     sar=SegmentationAndReassembly.UNSEGMENTED,
                     payload=None):
        frame = l2cap_packets.EnhancedInformationFrameBuilder(
            self._dcid, tx_seq, f, req_seq, sar, payload)
        self._acl.send(frame.Serialize())

    def send_s_frame(self,
                     req_seq,
                     s=SupervisoryFunction.RECEIVER_READY,
                     p=Poll.NOT_SET,
                     f=Final.NOT_SET):
        frame = l2cap_packets.EnhancedSupervisoryFrameBuilder(
            self._dcid, s, p, f, req_seq)
        self._acl.send(frame.Serialize())

    def send_information_request(self, type):
        assertThat(self._scid).isEqualTo(1)
        signal_id = 3
        information_request = l2cap_packets.InformationRequestBuilder(
            signal_id, type)
        self.send(information_request)

    def send_extended_features_request(self):
        self.send_information_request(
            InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED)

    def disconnect_and_verify(self):
        assertThat(self._scid).isNotEqualTo(1)
        self._control_channel.send(
            l2cap_packets.DisconnectionRequestBuilder(1, self._dcid,
                                                      self._scid))

        assertThat(self._control_channel).emits(
            L2capMatchers.DisconnectionResponse(self._scid, self._dcid))

    def verify_disconnect_request(self):
        assertThat(self._control_channel).emits(
            L2capMatchers.DisconnectionRequest(self._dcid, self._scid))


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

        self.support_ertm = True
        self.support_fcs = True

        self.basic_option = None
        self.ertm_option = None
        self.fcs_option = None

        self.config_response_result = l2cap_packets.ConfigurationResponseResult.SUCCESS
        self.config_response_options = []

    def close(self):
        self._acl_manager.close()
        safeClose(self._acl)

    def connect_acl(self, remote_addr):
        self._acl = self._acl_manager.initiate_connection(remote_addr)
        self._acl.wait_for_connection_complete()
        self.control_channel = CertL2capChannel(
            self._device,
            1,
            1,
            self._get_acl_stream(),
            self._acl,
            control_channel=None)
        self._get_acl_stream().register_callback(self._handle_control_packet)

    def open_channel(self, signal_id, psm, scid):
        self.control_channel.send(
            l2cap_packets.ConnectionRequestBuilder(signal_id, psm, scid))

        response = L2capCaptures.ConnectionResponse(scid)
        assertThat(self.control_channel).emits(response)
        return CertL2capChannel(self._device, scid,
                                response.get().GetDestinationCid(),
                                self._get_acl_stream(), self._acl,
                                self.control_channel)

    def verify_and_respond_open_channel_from_remote(self, psm=0x33):
        request = L2capCaptures.ConnectionRequest(psm)
        assertThat(self.control_channel).emits(request)

        sid = request.get().GetIdentifier()
        cid = request.get().GetSourceCid()

        self.scid_to_dcid[cid] = cid

        connection_response = l2cap_packets.ConnectionResponseBuilder(
            sid, cid, cid, l2cap_packets.ConnectionResponseResult.SUCCESS,
            l2cap_packets.ConnectionResponseStatus.
            NO_FURTHER_INFORMATION_AVAILABLE)
        self.control_channel.send(connection_response)

        config_options = []
        if self.basic_option is not None:
            config_options.append(self.basic_option)
        elif self.ertm_option is not None:
            config_options.append(self.ertm_option)
        if self.fcs_option is not None:
            config_options.append(self.fcs_option)

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, cid, l2cap_packets.Continuation.END, config_options)
        self.control_channel.send(config_request)

        channel = CertL2capChannel(self._device, cid, cid,
                                   self._get_acl_stream(), self._acl,
                                   self.control_channel)
        return channel

    # prefer to use channel abstraction instead, if at all possible
    def send_acl(self, packet):
        self._acl.send(packet.Serialize())

    def get_control_channel(self):
        return self.control_channel

    def _get_acl_stream(self):
        return self._acl_manager.get_acl_stream()

    # Disable ERTM when exchange extened feature
    def disable_ertm(self):
        self.support_ertm = False

    # Disable FCS when exchange extened feature
    def disable_fcs(self):
        self.support_fcs = False

    def turn_on_ertm(self, tx_window_size=10, max_transmit=20):
        self.ertm_option = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        self.ertm_option.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.ENHANCED_RETRANSMISSION
        self.ertm_option.tx_window_size = tx_window_size
        self.ertm_option.max_transmit = max_transmit
        self.ertm_option.retransmission_time_out = 2000
        self.ertm_option.monitor_time_out = 12000
        self.ertm_option.maximum_pdu_size = 1010

    def turn_on_fcs(self):
        self.fcs_option = l2cap_packets.FrameCheckSequenceOption()
        self.fcs_option.fcs_type = l2cap_packets.FcsType.DEFAULT

    # more of a hack for the moment
    def ignore_config_and_connections(self):
        self.control_table[CommandCode.CONFIGURATION_REQUEST] = lambda _: True
        self.control_table[CommandCode.CONNECTION_RESPONSE] = lambda _: True

    # more of a hack for the moment
    def ignore_config_request(self):
        self.control_table[CommandCode.CONFIGURATION_REQUEST] = lambda _: True

    # more of a hack for the moment
    def reply_with_unknown_options_and_hint(self):
        self.control_table[
            CommandCode.
            CONNECTION_RESPONSE] = self._on_connection_response_configuration_request_with_unknown_options_and_hint

    # more of a hack for the moment
    def reply_with_continuation_flag(self):
        self.control_table[
            CommandCode.
            CONNECTION_RESPONSE] = self._on_connection_response_configuration_request_with_continuation_flag

    # more of a hack for the moment
    def reply_with_nothing(self):
        self.control_table[
            CommandCode.
            CONNECTION_RESPONSE] = self._on_connection_response_do_nothing

    # more of a hack for the moment
    # Send configuration request after receive configuration request
    def config_with_basic_mode(self):
        self.control_table[
            CommandCode.
            CONFIGURATION_REQUEST] = self._on_configuration_request_send_configuration_request_basic_mode

    def set_config_response_result(self, result):
        """
        Set the result for config response packet
        """
        self.config_response_result = result

    def set_config_response_options(self, options):
        """
        Set the options (list) for config response packet
        """
        self.config_response_options = options

    def _on_connection_request_default(self, l2cap_control_view):
        pass

    def _on_connection_response_default(self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

        options = []
        if self.basic_option is not None:
            options.append(self.basic_option)
        elif self.ertm_option is not None:
            options.append(self.ertm_option)
        if self.fcs_option is not None:
            options.append(self.fcs_option)

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.END, options)
        self.control_channel.send(config_request)
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

    def _on_connection_response_configuration_request_with_continuation_flag(
            self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = 0x1234

        options = [mtu_opt]
        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, dcid, l2cap_packets.Continuation.CONTINUE, options)

        self.control_channel.send(config_request)

        flush_timeout_option = l2cap_packets.FlushTimeoutConfigurationOption()
        flush_timeout_option.flush_timeout = 65535
        option = [flush_timeout_option]
        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 2, dcid, l2cap_packets.Continuation.END, option)
        self.get_control_channel().send(config_request)
        return True

    def _on_connection_response_do_nothing(self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

    def _on_configuration_request_default(self, l2cap_control_view):
        configuration_request = l2cap_packets.ConfigurationRequestView(
            l2cap_control_view)
        sid = configuration_request.GetIdentifier()
        dcid = configuration_request.GetDestinationCid()
        config_response = l2cap_packets.ConfigurationResponseBuilder(
            sid, self.scid_to_dcid.get(dcid, 0), l2cap_packets.Continuation.END,
            self.config_response_result, self.config_response_options)
        self.control_channel.send(config_response)

    def reply_with_unacceptable_parameters(self):
        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = 123
        fcs_opt = l2cap_packets.FrameCheckSequenceOption()
        fcs_opt.fcs_type = l2cap_packets.FcsType.DEFAULT
        rfc_opt = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        rfc_opt.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.L2CAP_BASIC

        self.set_config_response_result(
            l2cap_packets.ConfigurationResponseResult.UNACCEPTABLE_PARAMETERS)
        self.set_config_response_options([mtu_opt, fcs_opt, rfc_opt])

    def reply_with_basic_mode(self):
        basic_option = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        basic_option.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.L2CAP_BASIC

        self.set_config_response_result(
            l2cap_packets.ConfigurationResponseResult.UNACCEPTABLE_PARAMETERS)
        self.set_config_response_options([basic_option])

    def reply_with_max_transmit_one(self):
        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = 123
        fcs_opt = l2cap_packets.FrameCheckSequenceOption()
        fcs_opt.fcs_type = l2cap_packets.FcsType.DEFAULT
        rfc_opt = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        rfc_opt.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.ENHANCED_RETRANSMISSION
        rfc_opt.tx_window_size = 10
        rfc_opt.max_transmit = 1
        rfc_opt.retransmission_time_out = 10
        rfc_opt.monitor_time_out = 10
        rfc_opt.maximum_pdu_size = 1010

        self.set_config_response_options([mtu_opt, fcs_opt, rfc_opt])

    def _on_configuration_request_send_configuration_request_basic_mode(
            self, l2cap_control_view):
        configuration_request = l2cap_packets.ConfigurationRequestView(
            l2cap_control_view)
        sid = configuration_request.GetIdentifier()
        dcid = configuration_request.GetDestinationCid()

        basic_option = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        basic_option.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.L2CAP_BASIC

        config_request = l2cap_packets.ConfigurationRequestBuilder(
            sid + 1, self.scid_to_dcid.get(dcid, 0),
            l2cap_packets.Continuation.END, [basic_option])
        self.control_channel.send(config_request)

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
        self.control_channel.send(disconnection_response)

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
            self.control_channel.send(response)
            return
        if information_type == l2cap_packets.InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED:
            response = l2cap_packets.InformationResponseExtendedFeaturesBuilder(
                sid, l2cap_packets.InformationRequestResult.SUCCESS, 0, 0, 0,
                self.support_ertm, 0, self.support_fcs, 0, 0, 0, 0)
            self.control_channel.send(response)
            return
        if information_type == l2cap_packets.InformationRequestInfoType.FIXED_CHANNELS_SUPPORTED:
            response = l2cap_packets.InformationResponseFixedChannelsBuilder(
                sid, l2cap_packets.InformationRequestResult.SUCCESS, 2)
            self.control_channel.send(response)
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
