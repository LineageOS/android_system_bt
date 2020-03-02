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

import bluetooth_packets_python3 as bt_packets
from bluetooth_packets_python3 import l2cap_packets
from bluetooth_packets_python3.l2cap_packets import CommandCode
from bluetooth_packets_python3.l2cap_packets import ConnectionResponseResult


class L2capMatchers(object):

    @staticmethod
    def ConnectionResponse(scid):
        return lambda packet: L2capMatchers._is_matching_connection_response(packet, scid)

    @staticmethod
    def ConnectionRequest():
        return lambda packet: L2capMatchers._is_control_frame_with_code(packet, CommandCode.CONNECTION_REQUEST)

    @staticmethod
    def ConfigurationResponse():
        return lambda packet: L2capMatchers._is_control_frame_with_code(packet, CommandCode.CONFIGURATION_RESPONSE)

    @staticmethod
    def ConfigurationRequest():
        return lambda packet: L2capMatchers._is_control_frame_with_code(packet, CommandCode.CONFIGURATION_REQUEST)

    @staticmethod
    def DisconnectionRequest():
        return lambda packet: L2capMatchers._is_control_frame_with_code(packet, CommandCode.DISCONNECTION_REQUEST)

    @staticmethod
    def _basic_frame(packet):
        if packet is None:
            return None
        return l2cap_packets.BasicFrameView(
            bt_packets.PacketViewLittleEndian(list(packet.payload)))

    @staticmethod
    def _control_frame(packet):
        frame = L2capMatchers._basic_frame(packet)
        if frame is None or frame.GetChannelId() != 1:
            return None
        return l2cap_packets.ControlView(frame.GetPayload())

    @staticmethod
    def _control_frame_with_code(packet, code):
        frame = L2capMatchers._control_frame(packet)
        if frame is None or frame.GetCode() != code:
            return None
        return frame

    @staticmethod
    def _is_control_frame_with_code(packet, code):
        return L2capMatchers._control_frame_with_code(packet, code) is not None

    @staticmethod
    def _is_matching_connection_response(packet, scid):
        frame = L2capMatchers._control_frame_with_code(
            packet, CommandCode.CONNECTION_RESPONSE)
        if frame is None:
            return False
        response = l2cap_packets.ConnectionResponseView(frame)
        return response.GetSourceCid() == scid and response.GetResult(
        ) == ConnectionResponseResult.SUCCESS and response.GetDestinationCid(
        ) != 0
