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
from cert.capture import Capture


def ReadBdAddrCompleteCapture():
    return Capture(lambda packet: b'\x0e\x0a\x01\x09\x10' in packet.event,
      lambda packet: hci_packets.ReadBdAddrCompleteView(
                  hci_packets.CommandCompleteView(
                            hci_packets.EventPacketView(
                                bt_packets.PacketViewLittleEndian(
                                    list(packet.event))))))


def ConnectionRequestCapture():
    return Capture(lambda packet: b'\x04\x0a' in packet.event,
      lambda packet: hci_packets.ConnectionRequestView(
                            hci_packets.EventPacketView(
                                bt_packets.PacketViewLittleEndian(
                                    list(packet.event)))))


def ConnectionCompleteCapture():
    return Capture(lambda packet: b'\x03\x0b\x00' in packet.event,
      lambda packet: hci_packets.ConnectionCompleteView(
                            hci_packets.EventPacketView(
                                bt_packets.PacketViewLittleEndian(
                                    list(packet.event)))))
