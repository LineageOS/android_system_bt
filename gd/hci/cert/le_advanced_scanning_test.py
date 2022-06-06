#!/usr/bin/env python3
#
#   Copyright 2021 - The Android Open Source Project
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

import queue
import logging

from google.protobuf import empty_pb2 as empty_proto

from bluetooth_packets_python3 import hci_packets
from cert.bt_constants import ble_scan_settings_modes, ble_address_types, scan_result, ble_scan_settings_phys
from cert.ble_lib import generate_ble_scan_objects
from cert.gd_sl4a_base_test import GdSl4aBaseTestClass
from hci.facade import \
  le_advertising_manager_facade_pb2 as le_advertising_facade
from hci.facade import le_initiator_address_facade_pb2 as le_initiator_address_facade
from facade import common_pb2 as common


class LeAdvancedScanningTest(GdSl4aBaseTestClass):

    def setup_class(self):
        super().setup_class(cert_module='HCI_INTERFACES')
        self.default_timeout = 10  # seconds

    def setup_test(self):
        super().setup_test()

    def teardown_test(self):
        super().teardown_test()

    def set_cert_privacy_policy_with_random_address(self, random_address):
        private_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_STATIC_ADDRESS,
            address_with_type=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=bytes(random_address, encoding='utf8')),
                type=common.RANDOM_DEVICE_ADDRESS))
        self.cert.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(private_policy)

    def set_cert_privacy_policy_with_public_address(self):
        public_address_bytes = self.cert.hci_controller.GetMacAddress(empty_proto.Empty()).address
        private_policy = le_initiator_address_facade.PrivacyPolicy(
            address_policy=le_initiator_address_facade.AddressPolicy.USE_PUBLIC_ADDRESS,
            address_with_type=common.BluetoothAddressWithType(
                address=common.BluetoothAddress(address=public_address_bytes), type=common.PUBLIC_DEVICE_ADDRESS))
        self.cert.hci_le_initiator_address.SetPrivacyPolicyForInitiatorAddress(private_policy)
        # Bluetooth MAC address must be upper case
        return public_address_bytes.decode('utf-8').upper()

    def test_scan_filter_device_name_legacy_pdu(self):
        # Use public address on cert side
        logging.info("Setting public address")
        DEVICE_NAME = 'Im_The_CERT!'
        public_address = self.set_cert_privacy_policy_with_public_address()
        logging.info("Set public address")

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_PUBLIC_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES,
            tx_power=20)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.CreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        logging.info("Start scanning with public address %s" % public_address)
        self.dut.droid.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.droid)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.droid.bleSetScanFilterDeviceName(DEVICE_NAME)
        self.dut.droid.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.droid.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            self.log.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        self.log.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.droid.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_random_address_legacy_pdu(self):
        # Use random address on cert side
        logging.info("Setting random address")
        RANDOM_ADDRESS = 'D0:05:04:03:02:01'
        DEVICE_NAME = 'Im_The_CERT!'
        self.set_cert_privacy_policy_with_random_address(RANDOM_ADDRESS)
        logging.info("Set random address")

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_RANDOM_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        request = le_advertising_facade.CreateAdvertiserRequest(config=config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.CreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["random"]
        logging.info("Start scanning for RANDOM_ADDRESS %s with address type %d" % (RANDOM_ADDRESS, addr_type))
        self.dut.droid.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.droid)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.droid.bleSetScanFilterDeviceAddressAndType(RANDOM_ADDRESS, int(addr_type))
        self.dut.droid.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.droid.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            self.log.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        self.log.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.droid.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True

    def test_scan_filter_device_public_address_extended_pdu(self):
        # Use public address on cert side
        logging.info("Setting public address")
        DEVICE_NAME = 'Im_The_CERT!'
        public_address = self.set_cert_privacy_policy_with_public_address()
        logging.info("Set public address")

        # Setup cert side to advertise
        gap_name = hci_packets.GapData()
        gap_name.data_type = hci_packets.GapDataType.COMPLETE_LOCAL_NAME
        gap_name.data = list(bytes(DEVICE_NAME, encoding='utf8'))
        gap_data = le_advertising_facade.GapDataMsg(data=bytes(gap_name.Serialize()))
        config = le_advertising_facade.AdvertisingConfig(
            advertisement=[gap_data],
            interval_min=512,
            interval_max=768,
            advertising_type=le_advertising_facade.AdvertisingEventType.ADV_IND,
            own_address_type=common.USE_PUBLIC_DEVICE_ADDRESS,
            channel_map=7,
            filter_policy=le_advertising_facade.AdvertisingFilterPolicy.ALL_DEVICES)
        extended_config = le_advertising_facade.ExtendedAdvertisingConfig(
            advertising_config=config, secondary_advertising_phy=ble_scan_settings_phys["1m"])
        request = le_advertising_facade.ExtendedCreateAdvertiserRequest(config=extended_config)
        logging.info("Creating advertiser")
        create_response = self.cert.hci_le_advertising_manager.ExtendedCreateAdvertiser(request)
        logging.info("Created advertiser")

        # Setup SL4A DUT side to scan
        addr_type = ble_address_types["public"]
        logging.info("Start scanning for PUBLIC_ADDRESS %s with address type %d" % (public_address, addr_type))
        self.dut.droid.bleSetScanSettingsScanMode(ble_scan_settings_modes['low_latency'])
        self.dut.droid.bleSetScanSettingsLegacy(False)
        filter_list, scan_settings, scan_callback = generate_ble_scan_objects(self.dut.droid)
        expected_event_name = scan_result.format(scan_callback)

        # Setup SL4A DUT filter
        self.dut.droid.bleSetScanFilterDeviceAddressAndType(public_address, int(addr_type))
        self.dut.droid.bleBuildScanFilter(filter_list)

        # Start scanning on SL4A DUT side
        self.dut.droid.bleStartBleScan(filter_list, scan_settings, scan_callback)
        logging.info("Started scanning")
        try:
            # Verify if there is scan result
            event_info = self.dut.ed.pop_event(expected_event_name, self.default_timeout)
        except queue.Empty as error:
            self.log.error("Could not find initial advertisement.")
            return False
        # Print out scan result
        mac_address = event_info['data']['Result']['deviceInfo']['address']
        self.log.info("Filter advertisement with address {}".format(mac_address))

        # Stop scanning
        logging.info("Stop scanning")
        self.dut.droid.bleStopBleScan(scan_callback)
        logging.info("Stopped scanning")

        # Stop advertising
        logging.info("Stop advertising")
        remove_request = le_advertising_facade.RemoveAdvertiserRequest(advertiser_id=create_response.advertiser_id)
        self.cert.hci_le_advertising_manager.RemoveAdvertiser(remove_request)
        logging.info("Stopped advertising")

        return True
