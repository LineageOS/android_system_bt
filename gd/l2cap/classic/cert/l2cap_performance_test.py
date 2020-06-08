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

from datetime import datetime, timedelta

from bluetooth_packets_python3 import RawBuilder
from cert.matchers import L2capMatchers
from cert.truth import assertThat
from cert.performance_test_logger import PerformanceTestLogger
from l2cap.classic.cert.cert_l2cap import CertL2cap
from l2cap.classic.cert.l2cap_test import L2capTestBase
from l2cap.classic.facade_pb2 import RetransmissionFlowControlMode
from bluetooth_packets_python3.l2cap_packets import FcsType
from bluetooth_packets_python3.l2cap_packets import SupervisoryFunction


class L2capPerformanceTest(L2capTestBase):

    def setup_test(self):
        super().setup_test()
        self.performance_test_logger = PerformanceTestLogger()

    def teardown_test(self):
        super().teardown_test()

    def _basic_mode_tx(self, mtu, packets):
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel_from_cert()
        self.performance_test_logger.start_interval("TX")
        for _ in range(packets):
            dut_channel.send(b'a' * mtu)
        assertThat(cert_channel).emits(
            L2capMatchers.Data(b'a' * mtu), at_least_times=packets, timeout=timedelta(seconds=60))
        self.performance_test_logger.end_interval("TX")

        duration = self.performance_test_logger.get_duration_of_intervals("TX")[0]
        self.log.info("Duration: %d" % duration)

    def _basic_mode_rx(self, mtu, packets):
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel_from_cert()
        self.performance_test_logger.start_interval("RX")
        data = b"a" * mtu
        data_packet = RawBuilder([x for x in data])
        for _ in range(packets):
            cert_channel.send(data_packet)
        assertThat(dut_channel).emits(
            L2capMatchers.PacketPayloadRawData(data), at_least_times=packets, timeout=timedelta(seconds=60))
        self.performance_test_logger.end_interval("RX")

        duration = self.performance_test_logger.get_duration_of_intervals("RX")[0]
        self.log.info("Duration: %d" % duration)

    def _ertm_mode_tx(self, mtu, packets, tx_window_size=10):
        # Make sure that number of packets is a multiple of tx_window_size
        packets = packets // tx_window_size * tx_window_size
        # For ERTM TX test, we have to do it sequentially because cert needs to ack
        self._setup_link_from_cert()

        config = CertL2cap.config_option_ertm(fcs=FcsType.NO_FCS, tx_window_size=tx_window_size)

        (dut_channel, cert_channel) = self._open_channel_from_cert(
            mode=RetransmissionFlowControlMode.ERTM,
            fcs=FcsType.NO_FCS,
            req_config_options=config,
            rsp_config_options=config)

        self.performance_test_logger.start_interval("TX")
        for i in range(packets):
            dut_channel.send(b'a' * mtu)
            if i % tx_window_size == tx_window_size - 1:
                assertThat(cert_channel).emits(L2capMatchers.IFrame(payload=b'a' * mtu), at_least_times=tx_window_size)
                cert_channel.send_s_frame(req_seq=(i + 1) % 64, s=SupervisoryFunction.RECEIVER_READY)

        self.performance_test_logger.end_interval("TX")

        duration = self.performance_test_logger.get_duration_of_intervals("TX")[0]
        self.log.info("Duration: %d" % duration)

    def _ertm_mode_rx(self, mtu, packets, tx_window_size=10):
        # Make sure that number of packets is a multiple of tx_window_size
        packets = packets // tx_window_size * tx_window_size

        self._setup_link_from_cert()

        config = CertL2cap.config_option_ertm(fcs=FcsType.NO_FCS, tx_window_size=tx_window_size)

        (dut_channel, cert_channel) = self._open_channel_from_cert(
            mode=RetransmissionFlowControlMode.ERTM,
            fcs=FcsType.NO_FCS,
            req_config_options=config,
            rsp_config_options=config)

        data = b"a" * mtu
        data_packet = RawBuilder([x for x in data])
        self.performance_test_logger.start_interval("RX")
        for i in range(packets):
            cert_channel.send_i_frame(tx_seq=i % 64, req_seq=0, payload=data_packet)
            if i % tx_window_size == (tx_window_size - 1):
                assertThat(cert_channel).emits(L2capMatchers.SFrame(req_seq=(i + 1) % 64))
        self.performance_test_logger.end_interval("RX")

        duration = self.performance_test_logger.get_duration_of_intervals("RX")[0]
        self.log.info("Duration: %d" % duration)

    def test_basic_mode_tx_672_100(self):
        self._basic_mode_tx(672, 100)

    def test_basic_mode_tx_100_100(self):
        self._basic_mode_tx(100, 100)

    def test_ertm_mode_tx_672_100(self):
        self._ertm_mode_tx(672, 100)

    def test_basic_mode_rx_672_100(self):
        self._basic_mode_rx(672, 100)

    def test_ertm_mode_rx_672_100(self):
        self._ertm_mode_rx(672, 100)

    def test_basic_mode_end_to_end_latency(self):
        self._setup_link_from_cert()

        (dut_channel, cert_channel) = self._open_channel_from_cert()

        data = b"a" * 100
        data_packet = RawBuilder([x for x in data])
        for i in range(100):
            self.performance_test_logger.start_interval("RX")
            cert_channel.send(data_packet)
            assertThat(dut_channel).emits(L2capMatchers.PacketPayloadRawData(data))
            self.performance_test_logger.end_interval("RX")
        duration = self.performance_test_logger.get_duration_of_intervals("RX")
        mean = sum(duration) / len(duration)
        self.log.info("Mean: %d" % mean)
