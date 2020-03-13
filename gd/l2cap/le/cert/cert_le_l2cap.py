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

    def send_first_le_i_frame(self, sdu_size, packet):
        frame = l2cap_packets.FirstLeInformationFrameBuilder(
            self._dcid, sdu_size, packet)
        self._acl.send(frame.Serialize())

    def disconnect_and_verify(self):
        assertThat(self._scid).isNotEqualTo(1)
        self._control_channel.send(
            l2cap_packets.DisconnectionRequestBuilder(1, self._dcid,
                                                      self._scid))

        assertThat(self._control_channel).emits(
            L2capMatchers.LeDisconnectionResponse(self._scid, self._dcid))

    def verify_disconnect_request(self):
        assertThat(self._control_channel).emits(
            L2capMatchers.LeDisconnectionRequest(self._dcid, self._scid))

    def send_credits(self, num_credits):
        self._control_channel.send(
            l2cap_packets.LeFlowControlCreditBuilder(2, self._scid,
                                                     num_credits))


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

    def open_channel(self,
                     signal_id,
                     psm,
                     scid,
                     mtu=1000,
                     mps=100,
                     initial_credit=6):
        self.control_channel.send(
            l2cap_packets.LeCreditBasedConnectionRequestBuilder(
                signal_id, psm, scid, mtu, mps, initial_credit))

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
