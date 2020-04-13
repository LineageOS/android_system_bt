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

from cert.behavior import IHasBehaviors, SingleArgumentBehavior, ReplyStage
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
from bluetooth_packets_python3.l2cap_packets import ConfigurationResponseResult
from cert.event_stream import FilteringEventStream
from cert.event_stream import IEventStream
from cert.matchers import L2capMatchers
from cert.captures import L2capCaptures


class CertL2capControlChannelBehaviors(object):

    def __init__(self, parent):
        self.on_packet_behavior = SingleArgumentBehavior(
            lambda: CertL2capControlChannelBehaviors.CertReplyStage(parent))

    def on_packet(self, matcher):
        return self.on_packet_behavior.begin(matcher)

    class CertReplyStage(ReplyStage):

        def __init__(self, parent):
            self.parent = parent

        def send_packet(self):
            self._commit(lambda packet: self._send_packet(packet))
            return self

        def _send_packet(self, packet):
            self.parent._control_channel.send(packet)


class CertL2capChannel(IEventStream, IHasBehaviors):

    def __init__(self,
                 device,
                 scid,
                 dcid,
                 acl_stream,
                 acl,
                 control_channel,
                 fcs=None):
        self._device = device
        self._scid = scid
        self._dcid = dcid
        self._acl_stream = acl_stream
        self._acl = acl
        self._control_channel = control_channel
        self.control_behaviors = CertL2capControlChannelBehaviors(self)
        if fcs == l2cap_packets.FcsType.DEFAULT:
            self._our_acl_view = FilteringEventStream(
                acl_stream, L2capMatchers.ExtractBasicFrameWithFcs(scid))
        else:
            self._our_acl_view = FilteringEventStream(
                acl_stream, L2capMatchers.ExtractBasicFrame(scid))

    def get_behaviors(self):
        return self.control_behaviors

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
                     payload=None,
                     fcs=False):
        if fcs:
            frame = l2cap_packets.EnhancedInformationFrameWithFcsBuilder(
                self._dcid, tx_seq, f, req_seq, sar, payload)
        else:
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

    def send_configure_request(self,
                               options,
                               sid=2,
                               continuation=l2cap_packets.Continuation.END):
        assertThat(self._scid).isNotEqualTo(1)
        request = l2cap_packets.ConfigurationRequestBuilder(
            2, self._dcid, l2cap_packets.Continuation.END, options)
        self._control_channel.send(request)

    def send_information_request(self, type):
        assertThat(self._scid).isEqualTo(1)
        signal_id = 3
        information_request = l2cap_packets.InformationRequestBuilder(
            signal_id, type)
        self.send(information_request)

    def send_extended_features_request(self):
        self.send_information_request(
            InformationRequestInfoType.EXTENDED_FEATURES_SUPPORTED)

    def verify_configuration_request_and_respond(
            self, result=ConfigurationResponseResult.SUCCESS, options=None):
        request_capture = L2capCaptures.ConfigurationRequest(self._scid)
        assertThat(self._control_channel).emits(request_capture)
        request = request_capture.get()
        sid = request.GetIdentifier()
        if options is None:
            options = []
        config_response = l2cap_packets.ConfigurationResponseBuilder(
            sid, self._dcid, l2cap_packets.Continuation.END, result, options)
        self._control_channel.send(config_response)

    def verify_configuration_response(self):
        assertThat(self._control_channel).emits(
            L2capMatchers.ConfigurationResponse())

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
        self.scid_to_channel = {}

        self.support_ertm = True
        self.support_fcs = True

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

    def open_channel(self, signal_id, psm, scid, fcs=None):
        self.control_channel.send(
            l2cap_packets.ConnectionRequestBuilder(signal_id, psm, scid))

        response = L2capCaptures.ConnectionResponse(scid)
        assertThat(self.control_channel).emits(response)
        channel = CertL2capChannel(self._device, scid,
                                   response.get().GetDestinationCid(),
                                   self._get_acl_stream(), self._acl,
                                   self.control_channel, fcs)
        self.scid_to_channel[scid] = channel

        return channel

    def verify_and_respond_open_channel_from_remote(self,
                                                    psm=0x33,
                                                    scid=None,
                                                    fcs=None):

        request = L2capCaptures.ConnectionRequest(psm)
        assertThat(self.control_channel).emits(request)

        sid = request.get().GetIdentifier()
        dcid = request.get().GetSourceCid()
        if scid is None or scid in self.scid_to_dcid:
            scid = dcid

        self.scid_to_dcid[scid] = dcid

        channel = CertL2capChannel(self._device, scid, dcid,
                                   self._get_acl_stream(), self._acl,
                                   self.control_channel, fcs)
        self.scid_to_channel[scid] = channel

        connection_response = l2cap_packets.ConnectionResponseBuilder(
            sid, scid, dcid, l2cap_packets.ConnectionResponseResult.SUCCESS,
            l2cap_packets.ConnectionResponseStatus.
            NO_FURTHER_INFORMATION_AVAILABLE)
        self.control_channel.send(connection_response)

        return channel

    # prefer to use channel abstraction instead, if at all possible
    def send_acl(self, packet):
        self._acl.send(packet.Serialize())

    def get_control_channel(self):
        return self.control_channel

    def _get_acl_stream(self):
        return self._acl_manager.get_acl_stream()

    # Disable ERTM when exchange extened feature
    def claim_ertm_unsupported(self):
        self.support_ertm = False

    def turn_on_ertm(self, tx_window_size=10, max_transmit=20, mps=1010):
        pass

    # more of a hack for the moment
    def reply_with_unknown_options_and_hint(self):
        self.control_table[
            CommandCode.
            CONNECTION_RESPONSE] = self._on_connection_response_configuration_request_with_unknown_options_and_hint

    def _on_connection_response_default(self, l2cap_control_view):
        pass

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
        pass

    @staticmethod
    def config_option_basic_explicit(mtu=642):
        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = mtu
        rfc_opt = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        rfc_opt.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.L2CAP_BASIC
        return [mtu_opt, rfc_opt]

    @staticmethod
    def config_option_mtu_explicit(mtu=642):
        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = mtu
        return [mtu_opt]

    @staticmethod
    def config_option_ertm(mtu=642,
                           fcs=None,
                           max_transmit=10,
                           mps=1010,
                           tx_window_size=10,
                           monitor_time_out=2000):
        result = []
        mtu_opt = l2cap_packets.MtuConfigurationOption()
        mtu_opt.mtu = mtu
        result.append(mtu_opt)
        if fcs is not None:
            fcs_opt = l2cap_packets.FrameCheckSequenceOption()
            fcs_opt.fcs_type = fcs
            result.append(fcs_opt)
        rfc_opt = l2cap_packets.RetransmissionAndFlowControlConfigurationOption(
        )
        rfc_opt.mode = l2cap_packets.RetransmissionAndFlowControlModeOption.ENHANCED_RETRANSMISSION
        rfc_opt.tx_window_size = tx_window_size
        rfc_opt.max_transmit = max_transmit
        rfc_opt.retransmission_time_out = 1000
        rfc_opt.monitor_time_out = monitor_time_out
        rfc_opt.maximum_pdu_size = mps
        result.append(rfc_opt)
        return result

    @staticmethod
    def config_option_ertm_with_max_transmit_one():
        return CertL2cap.config_option_ertm(max_transmit=1)

    @staticmethod
    def config_option_ertm_with_mps(mps=1010):
        return CertL2cap.config_option_ertm(mps=mps)

    def _on_configuration_response_default(self, l2cap_control_view):
        pass

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
        pass

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
        pass

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
