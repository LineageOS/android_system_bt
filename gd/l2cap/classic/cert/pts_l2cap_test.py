from cert.pts_base_test import PTSBaseTestClass
from facade import common_pb2
from facade import rootservice_pb2 as facade_rootservice_pb2
from l2cap.classic import facade_pb2 as l2cap_facade_pb2
from google.protobuf import empty_pb2

from datetime import timedelta
import time
class PTSL2capTest(PTSBaseTestClass):
    def setup_test(self):
        self.device_under_test = self.gd_devices[0]

        self.device_under_test.rootservice.StartStack(
            facade_rootservice_pb2.StartStackRequest(
                module_under_test=facade_rootservice_pb2.BluetoothModule.Value('L2CAP'),
            )
        )

        self.device_under_test.wait_channel_ready()

        dut_address = self.device_under_test.controller_read_only_property.ReadLocalAddress(empty_pb2.Empty()).address
        pts_address = self.controller_configs.get('pts_address').lower()
        self.device_under_test.address = dut_address

        self.dut_address = common_pb2.BluetoothAddress(
            address=self.device_under_test.address)
        self.pts_address = common_pb2.BluetoothAddress(
            address=str.encode(pts_address))

    def teardown_test(self):
        self.device_under_test.rootservice.StopStack(
            facade_rootservice_pb2.StopStackRequest()
        )

    def _pending_connection_complete(self, timeout=30):
        dut_connection_stream = self.device_under_test.l2cap.connection_complete_stream
        dut_connection_stream.subscribe()
        dut_connection_stream.assert_event_occurs(
          lambda device : device.remote.address == self.pts_address.address,
          timeout=timedelta(seconds=timeout)
        )
        dut_connection_stream.unsubscribe()

    def _pending_connection_close(self, timeout=30):
        dut_connection_close_stream = self.device_under_test.l2cap.connection_close_stream
        dut_connection_close_stream.subscribe()
        dut_connection_close_stream.assert_event_occurs(
          lambda device : device.remote.address == self.pts_address.address,
          timeout=timedelta(seconds=timeout)
        )
        dut_connection_close_stream.unsubscribe()

    def test_L2CAP_COS_CED_BV_01_C(self):
        """
        L2CAP/COS/CED/BV-01-C [Request Connection]
        Verify that the IUT is able to request the connection establishment for an L2CAP data channel and
        initiate the configuration procedure.
        """
        psm = 1
        self.device_under_test.l2cap.OpenChannel(l2cap_facade_pb2.OpenChannelRequest(remote=self.pts_address, psm=psm))
        self._pending_connection_complete()
        self.device_under_test.l2cap.CloseChannel(l2cap_facade_pb2.CloseChannelRequest(psm=psm))
        self._pending_connection_close()

    def test_L2CAP_COS_CED_BV_03_C(self):
        """
        L2CAP/COS/CED/BV-03-C [Send Data]
        Verify that the IUT is able to send DATA.
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_complete()
        self.device_under_test.l2cap.SendDynamicChannelPacket(l2cap_facade_pb2.DynamicChannelPacket(psm=psm, payload=b'abc'*34))
        self._pending_connection_close()

    def test_L2CAP_COS_CED_BV_04_C(self):
        """
        L2CAP/COS/CED/BV-04-C [Disconnect]
        Verify that the IUT is able to disconnect the data channel.
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_complete()
        time.sleep(2)
        self.device_under_test.l2cap.CloseChannel(l2cap_facade_pb2.CloseChannelRequest(psm=psm))
        self._pending_connection_close()

    def test_L2CAP_COS_CED_BV_05_C(self):
        """
        L2CAP/COS/CED/BV-05-C [Accept Connection]
        Verify that the IUT is able to disconnect the data channel.
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_complete()
        self._pending_connection_close()

    def test_L2CAP_COS_CED_BV_07_C(self):
        """
        L2CAP/COS/CED/BV-07-C [Accept Disconnect]
        Verify that the IUT is able to respond to the request to disconnect the data channel.
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_complete()
        self._pending_connection_close()

    def test_L2CAP_COS_CED_BV_08_C(self):
        """
        L2CAP/COS/CED/BV-08-C [Disconnect on Timeout]
        Verify that the IUT disconnects the data channel and shuts down this channel if no response occurs
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))

        time.sleep(120)

    def test_L2CAP_COS_CED_BV_09_C(self):
        """
        L2CAP/COS/CED/BV-09-C [Receive Multi-Command Packet]
        Verify that the IUT is able to receive more than one signaling command in one L2CAP packet.
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_complete()
        self._pending_connection_close()

    def test_L2CAP_COS_CED_BV_11_C(self):
        """
        L2CAP/COS/CED/BV-11-C [Configure MTU Size]
        Verify that the IUT is able to configure the supported MTU size
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_complete()
        self._pending_connection_close()

    def test_L2CAP_COS_CED_BI_01_C(self):
        """
        L2CAP/COS/CED/BI-01-C [Reject Unknown Command]
        Verify that the IUT rejects an unknown signaling command.
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_complete()
        time.sleep(5)

    def test_L2CAP_COS_CFD_BV_03_C(self):
        """
        L2CAP/COS/CFD/BV-03-C [Send Requested Options]
        Verify that the IUT can receive a configuration request with no options and send the requested
        options to the Lower Tester
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.BASIC))
        self._pending_connection_close()

    def test_L2CAP_COS_CFD_BV_08_C(self):
        """
        L2CAP/COS/CFD/BV-08-C [Non-blocking Config Response]
        Verify that the IUT does not block transmitting L2CAP_ConfigRsp while waiting for L2CAP_ConfigRsp
        from the Lower Tester.
        """
        psm = 1
        self.device_under_test.l2cap.OpenChannel(l2cap_facade_pb2.OpenChannelRequest(remote=self.pts_address, psm=psm))
        self._pending_connection_complete()
        self.device_under_test.l2cap.CloseChannel(l2cap_facade_pb2.CloseChannelRequest(psm=psm))
        self._pending_connection_close()


    def test_L2CAP_ERM_BI_01_C(self):
        """
        L2CAP/ERM/BI-01-C [S-Frame [REJ] Lost or Corrupted]
        Verify the IUT can handle receipt of an S-=frame [RR] Poll = 1 if the S-frame [REJ] sent from the IUT
        is lost.
        """
        psm = 1
        self.device_under_test.l2cap.SetDynamicChannel(l2cap_facade_pb2.SetEnableDynamicChannelRequest(
            psm=psm, retransmission_mode=l2cap_facade_pb2.RetransmissionFlowControlMode.ERTM))
        self._pending_connection_complete()
        self._pending_connection_close(timeout=60)
