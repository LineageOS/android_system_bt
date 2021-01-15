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
from bluetooth_packets_python3 import hci_packets
from bluetooth_packets_python3 import l2cap_packets
from bluetooth_packets_python3.l2cap_packets import CommandCode, LeCommandCode
from cert.capture import Capture
from cert.matchers import HciMatchers
from cert.matchers import L2capMatchers
from cert.matchers import SecurityMatchers
from security.facade_pb2 import UiMsgType


class HalCaptures(object):

    @staticmethod
    def ReadBdAddrCompleteCapture():
        return Capture(
            lambda packet: packet.payload[0:5] == b'\x0e\x0a\x01\x09\x10', lambda packet: hci_packets.ReadBdAddrCompleteView(
                hci_packets.CommandCompleteView(
                    hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet.payload))))))

    @staticmethod
    def ConnectionRequestCapture():
        return Capture(
            lambda packet: packet.payload[0:2] == b'\x04\x0a', lambda packet: hci_packets.ConnectionRequestView(
                hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet.payload)))))

    @staticmethod
    def ConnectionCompleteCapture():
        return Capture(
            lambda packet: packet.payload[0:3] == b'\x03\x0b\x00', lambda packet: hci_packets.ConnectionCompleteView(
                hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet.payload)))))

    @staticmethod
    def DisconnectionCompleteCapture():
        return Capture(
            lambda packet: packet.payload[0:2] == b'\x05\x04', lambda packet: hci_packets.DisconnectionCompleteView(
                hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet.payload)))))

    @staticmethod
    def LeConnectionCompleteCapture():
        return Capture(
            lambda packet: packet.payload[0] == 0x3e and (packet.payload[2] == 0x01 or packet.payload[2] == 0x0a),
            lambda packet: hci_packets.LeConnectionCompleteView(
                hci_packets.LeMetaEventView(
                    hci_packets.EventView(bt_packets.PacketViewLittleEndian(list(packet.payload))))))


class HciCaptures(object):

    @staticmethod
    def ReadLocalOobDataCompleteCapture():
        return Capture(
            HciMatchers.CommandComplete(hci_packets.OpCode.READ_LOCAL_OOB_DATA),
            lambda packet: HciMatchers.ExtractMatchingCommandComplete(packet.payload, hci_packets.OpCode.READ_LOCAL_OOB_DATA)
        )

    @staticmethod
    def ReadLocalOobExtendedDataCompleteCapture():
        return Capture(
            HciMatchers.CommandComplete(hci_packets.OpCode.READ_LOCAL_OOB_EXTENDED_DATA),
            lambda packet: HciMatchers.ExtractMatchingCommandComplete(packet.payload, hci_packets.OpCode.READ_LOCAL_OOB_EXTENDED_DATA)
        )

    @staticmethod
    def ReadBdAddrCompleteCapture():
        return Capture(
            HciMatchers.CommandComplete(hci_packets.OpCode.READ_BD_ADDR),
            lambda packet: hci_packets.ReadBdAddrCompleteView(HciMatchers.ExtractMatchingCommandComplete(packet.payload, hci_packets.OpCode.READ_BD_ADDR)))

    @staticmethod
    def ConnectionRequestCapture():
        return Capture(
            HciMatchers.EventWithCode(hci_packets.EventCode.CONNECTION_REQUEST),
            lambda packet: hci_packets.ConnectionRequestView(
                HciMatchers.ExtractEventWithCode(packet.payload, hci_packets.EventCode.CONNECTION_REQUEST)))

    @staticmethod
    def ConnectionCompleteCapture():
        return Capture(
            HciMatchers.EventWithCode(hci_packets.EventCode.CONNECTION_COMPLETE),
            lambda packet: hci_packets.ConnectionCompleteView(
                HciMatchers.ExtractEventWithCode(packet.payload, hci_packets.EventCode.CONNECTION_COMPLETE)))

    @staticmethod
    def DisconnectionCompleteCapture():
        return Capture(
            HciMatchers.EventWithCode(hci_packets.EventCode.DISCONNECTION_COMPLETE),
            lambda packet: hci_packets.DisconnectionCompleteView(
                HciMatchers.ExtractEventWithCode(packet.payload, hci_packets.EventCode.DISCONNECTION_COMPLETE)))

    @staticmethod
    def LeConnectionCompleteCapture():
        return Capture(HciMatchers.LeConnectionComplete(),
                       lambda packet: HciMatchers.ExtractLeConnectionComplete(packet.payload))

    @staticmethod
    def SimplePairingCompleteCapture():
        return Capture(HciMatchers.EventWithCode(hci_packets.EventCode.SIMPLE_PAIRING_COMPLETE),
            lambda packet: hci_packets.SimplePairingCompleteView(
                HciMatchers.ExtractEventWithCode(packet.payload, hci_packets.EventCode.SIMPLE_PAIRING_COMPLETE)))


class L2capCaptures(object):

    @staticmethod
    def ConnectionRequest(psm):
        return Capture(L2capMatchers.ConnectionRequest(psm), L2capCaptures._extract_connection_request)

    @staticmethod
    def _extract_connection_request(packet):
        frame = L2capMatchers.control_frame_with_code(packet, CommandCode.CONNECTION_REQUEST)
        return l2cap_packets.ConnectionRequestView(frame)

    @staticmethod
    def ConnectionResponse(scid):
        return Capture(L2capMatchers.ConnectionResponse(scid), L2capCaptures._extract_connection_response)

    @staticmethod
    def _extract_connection_response(packet):
        frame = L2capMatchers.control_frame_with_code(packet, CommandCode.CONNECTION_RESPONSE)
        return l2cap_packets.ConnectionResponseView(frame)

    @staticmethod
    def ConfigurationRequest(cid=None):
        return Capture(L2capMatchers.ConfigurationRequest(cid), L2capCaptures._extract_configuration_request)

    @staticmethod
    def _extract_configuration_request(packet):
        frame = L2capMatchers.control_frame_with_code(packet, CommandCode.CONFIGURATION_REQUEST)
        return l2cap_packets.ConfigurationRequestView(frame)

    @staticmethod
    def CreditBasedConnectionRequest(psm):
        return Capture(
            L2capMatchers.CreditBasedConnectionRequest(psm), L2capCaptures._extract_credit_based_connection_request)

    @staticmethod
    def _extract_credit_based_connection_request(packet):
        frame = L2capMatchers.le_control_frame_with_code(packet, LeCommandCode.LE_CREDIT_BASED_CONNECTION_REQUEST)
        return l2cap_packets.LeCreditBasedConnectionRequestView(frame)

    @staticmethod
    def CreditBasedConnectionResponse():
        return Capture(L2capMatchers.CreditBasedConnectionResponse(),
                       L2capCaptures._extract_credit_based_connection_response)

    @staticmethod
    def _extract_credit_based_connection_response(packet):
        frame = L2capMatchers.le_control_frame_with_code(packet, LeCommandCode.LE_CREDIT_BASED_CONNECTION_RESPONSE)
        return l2cap_packets.LeCreditBasedConnectionResponseView(frame)

    @staticmethod
    def LinkSecurityInterfaceCallbackEvent(type):
        return Capture(L2capMatchers.LinkSecurityInterfaceCallbackEvent(type), L2capCaptures._extract_address)

    @staticmethod
    def _extract_address(packet):
        return packet.address


class SecurityCaptures(object):

    @staticmethod
    def DisplayPasskey():
        return Capture(SecurityMatchers.UiMsg(UiMsgType.DISPLAY_PASSKEY), SecurityCaptures._extract_passkey)

    @staticmethod
    def _extract_passkey(event):
        if event is None:
            return None
        return event.numeric_value
