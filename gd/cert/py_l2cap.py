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

from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from l2cap.le import facade_pb2 as l2cap_le_facade_pb2
from bluetooth_packets_python3 import l2cap_packets
from bluetooth_packets_python3.l2cap_packets import ConnectionResponseResult
from cert.event_stream import FilteringEventStream
from cert.event_stream import EventStream, IEventStream
from cert.closable import Closable, safeClose
from cert.truth import assertThat
from cert.matchers import L2capMatchers
from facade import common_pb2 as common
from google.protobuf import empty_pb2 as empty_proto


class PyL2capChannel(object):

    def __init__(self, device, psm):
        self._device = device
        self._psm = psm

    def send(self, payload):
        self._device.l2cap.SendDynamicChannelPacket(
            l2cap_facade_pb2.DynamicChannelPacket(psm=0x33, payload=payload))


class PyL2cap(Closable):

    def __init__(self, device):
        self._device = device

    def close(self):
        pass

    def open_channel(self,
                     psm=0x33,
                     mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC):

        # todo, I don't understand what SetDynamicChannel means?
        self._device.l2cap.SetDynamicChannel(
            l2cap_facade_pb2.SetEnableDynamicChannelRequest(
                psm=psm, retransmission_mode=mode))
        return PyL2capChannel(self._device, psm)


class PyLeL2capChannel(IEventStream):

    def __init__(self, device, psm, l2cap_stream):
        self._device = device
        self._psm = psm
        self._le_l2cap_stream = l2cap_stream
        self._our_le_l2cap_view = FilteringEventStream(
            self._le_l2cap_stream,
            L2capMatchers.PacketPayloadWithMatchingPsm(self._psm))

    def get_event_queue(self):
        return self._our_le_l2cap_view.get_event_queue()

    def send(self, payload):
        self._device.l2cap_le.SendDynamicChannelPacket(
            l2cap_le_facade_pb2.DynamicChannelPacket(psm=0x33, payload=payload))


class CreditBasedConnectionResponseFutureWrapper(object):
    """
    The future object returned when we send a connection request from DUT. Can be used to get connection status and
    create the corresponding PyLeL2capChannel object later
    """

    def __init__(self, grpc_response_future, device, psm, le_l2cap_stream):
        self._grpc_response_future = grpc_response_future
        self._device = device
        self._psm = psm
        self._le_l2cap_stream = le_l2cap_stream

    def get_status(self):
        return l2cap_packets.LeCreditBasedConnectionResponseResult(
            self._grpc_response_future.result().status)

    def get_channel(self):
        assertThat(self.get_status()).isEqualTo(
            l2cap_packets.LeCreditBasedConnectionResponseResult.SUCCESS)
        return PyLeL2capChannel(self._device, self._psm, self._le_l2cap_stream)


class PyLeL2cap(Closable):

    def __init__(self, device):
        self._device = device
        self._le_l2cap_stream = EventStream(
            self._device.l2cap_le.FetchL2capData(empty_proto.Empty()))

    def close(self):
        safeClose(self._le_l2cap_stream)

    def register_coc(self, psm=0x33):
        self._device.l2cap_le.SetDynamicChannel(
            l2cap_le_facade_pb2.SetEnableDynamicChannelRequest(
                psm=psm, enable=True))
        return PyLeL2capChannel(self._device, psm, self._le_l2cap_stream)

    def connect_coc_to_cert(self, psm=0x33):
        """
        Send open LE COC request to CERT. Get a future for connection result, to be used after CERT accepts request
        """
        self.register_coc(psm)
        # TODO: Update CERT device random address in ACL manager
        response_future = self._device.l2cap_le.OpenDynamicChannel.future(
            l2cap_le_facade_pb2.OpenDynamicChannelRequest(
                psm=psm,
                remote=common.BluetoothAddressWithType(
                    address=common.BluetoothAddress(
                        address=b"22:33:ff:ff:11:00"))))

        return CreditBasedConnectionResponseFutureWrapper(
            response_future, self._device, psm, self._le_l2cap_stream)
