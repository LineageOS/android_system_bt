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
from cert.py_le_acl_manager import PyLeAclManager
from cert.truth import assertThat
import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import l2cap_packets
from bluetooth_packets_python3.l2cap_packets import CommandCode
from cert.event_stream import FilteringEventStream
from cert.event_stream import IEventStream
from cert.matchers import L2capMatchers
from cert.captures import L2capCaptures


class CertLeL2capChannel(IEventStream):

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

    def disconnect_and_verify(self):
        assertThat(self._scid).isNotEqualTo(1)
        self._control_channel.send(
            l2cap_packets.DisconnectionRequestBuilder(1, self._dcid,
                                                      self._scid))

        assertThat(self._control_channel).emits(
            L2capMatchers.DisconnectionResponse(self._scid, self._dcid))


class CertLeL2cap(Closable):

    def __init__(self, device):
        self._device = device
        self._le_acl_manager = PyLeAclManager(device)
        self._le_acl = None

        self.control_table = {
            CommandCode.DISCONNECTION_REQUEST:
            self._on_disconnection_request_default,
            CommandCode.DISCONNECTION_RESPONSE:
            self._on_disconnection_response_default,
        }

        self.scid_to_dcid = {}

    def close(self):
        self._le_acl_manager.close()
        safeClose(self._le_acl)

    def connect_le_acl(self, remote_addr):
        self._le_acl = self._le_acl_manager.initiate_connection(remote_addr)
        self._le_acl.wait_for_connection_complete()
        self.control_channel = CertLeL2capChannel(
            self._device,
            5,
            5,
            self._get_acl_stream(),
            self._le_acl,
            control_channel=None)
        self._get_acl_stream().register_callback(self._handle_control_packet)

    def open_channel(self, signal_id, psm, scid):
        # TODO(hsz): use credit based
        self.control_channel.send(
            l2cap_packets.LeCreditBasedConnectionRequestBuilder(
                signal_id, psm, scid, 2000, 1000, 1000))

        response = L2capCaptures.CreditBasedConnectionResponse(scid)
        assertThat(self.control_channel).emits(response)
        return CertLeL2capChannel(self._device, scid,
                                  response.get().GetDestinationCid(),
                                  self._get_acl_stream(), self._le_acl,
                                  self.control_channel)

    # prefer to use channel abstraction instead, if at all possible
    def send_acl(self, packet):
        self._acl.send(packet.Serialize())

    def get_control_channel(self):
        return self.control_channel

    def _get_acl_stream(self):
        return self._le_acl_manager.get_le_acl_stream()

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
        self.control_channel.send(connection_response)
        return True

    def _on_connection_response_default(self, l2cap_control_view):
        connection_response_view = l2cap_packets.ConnectionResponseView(
            l2cap_control_view)
        sid = connection_response_view.GetIdentifier()
        scid = connection_response_view.GetSourceCid()
        dcid = connection_response_view.GetDestinationCid()
        self.scid_to_dcid[scid] = dcid

        options = []
        if self.ertm_option is not None:
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

    def _handle_control_packet(self, l2cap_packet):
        packet_bytes = l2cap_packet.payload
        l2cap_view = l2cap_packets.BasicFrameView(
            bt_packets.PacketViewLittleEndian(list(packet_bytes)))
        if l2cap_view.GetChannelId() != 5:
            return
        l2cap_control_view = l2cap_packets.ControlView(l2cap_view.GetPayload())
        fn = self.control_table.get(l2cap_control_view.GetCode())
        if fn is not None:
            fn(l2cap_control_view)
        return
