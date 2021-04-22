/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Generated mock file from original source file
 *   Functions generated:1
 *
 *  mockcify.pl ver 0.2
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

// Original included files, if any
// NOTE: Since this is a mock file with mock definitions some number of
//       include files may not be required.  The include-what-you-use
//       still applies, but crafting proper inclusion is out of scope
//       for this effort.  This compilation unit may compile as-is, or
//       may need attention to prune the inclusion set.
#include "bt_types.h"
#include "main/shim/controller.h"

// Mock include file to share data between tests and mock
#include "test/mock/mock_device_controller.h"

// Mocked compile conditionals, if any
#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

// Mocked internal structures, if any
namespace test {
namespace mock {
namespace device_controller {

RawAddress address;
bt_version_t bt_version = {
    .hci_version = 0,
    .hci_revision = 0,
    .lmp_version = 0,
    .manufacturer = 0,
    .lmp_subversion = 0,
};

uint8_t supported_commands[HCI_SUPPORTED_COMMANDS_ARRAY_SIZE]{0};
bt_device_features_t features_classic[MAX_FEATURES_CLASSIC_PAGE_COUNT] = {{
    .as_array{0},
}};
uint8_t last_features_classic_page_index{0};

uint16_t acl_data_size_classic{0};
uint16_t acl_data_size_ble{0};
uint16_t iso_data_size{0};

uint16_t acl_buffer_count_classic{0};
uint8_t acl_buffer_count_ble{0};
uint8_t iso_buffer_count{0};

uint8_t ble_acceptlist_size{0};
uint8_t ble_resolving_list_max_size{0};
uint8_t ble_supported_states[BLE_SUPPORTED_STATES_SIZE]{0};
bt_device_features_t features_ble{0};
uint16_t ble_suggested_default_data_length{0};
uint16_t ble_supported_max_tx_octets{0};
uint16_t ble_supported_max_tx_time{0};
uint16_t ble_supported_max_rx_octets{0};
uint16_t ble_supported_max_rx_time{0};

uint16_t ble_maxium_advertising_data_length{0};
uint8_t ble_number_of_supported_advertising_sets{0};
uint8_t ble_periodic_advertiser_list_size{0};
uint8_t local_supported_codecs[MAX_LOCAL_SUPPORTED_CODECS_SIZE]{0};
uint8_t number_of_local_supported_codecs{0};

bool readable{false};
bool ble_supported{false};
bool iso_supported{false};
bool simple_pairing_supported{false};
bool secure_connections_supported{false};

bool get_is_ready(void) { return readable; }

const RawAddress* get_address(void) { return &address; }

const bt_version_t* get_bt_version(void) { return &bt_version; }

uint8_t* get_local_supported_codecs(uint8_t* number_of_codecs) {
  if (number_of_local_supported_codecs) {
    *number_of_codecs = number_of_local_supported_codecs;
    return local_supported_codecs;
  }
  return NULL;
}

const uint8_t* get_ble_supported_states(void) { return ble_supported_states; }

bool supports_simple_pairing(void) { return simple_pairing_supported; }

bool supports_secure_connections(void) { return secure_connections_supported; }

bool supports_simultaneous_le_bredr(void) {
  return HCI_SIMUL_LE_BREDR_SUPPORTED(features_classic[0].as_array);
}

bool supports_reading_remote_extended_features(void) {
  return HCI_READ_REMOTE_EXT_FEATURES_SUPPORTED(supported_commands);
}

bool supports_interlaced_inquiry_scan(void) {
  return HCI_LMP_INTERLACED_INQ_SCAN_SUPPORTED(features_classic[0].as_array);
}

bool supports_rssi_with_inquiry_results(void) {
  return HCI_LMP_INQ_RSSI_SUPPORTED(features_classic[0].as_array);
}

bool supports_extended_inquiry_response(void) {
  return HCI_EXT_INQ_RSP_SUPPORTED(features_classic[0].as_array);
}

bool supports_central_peripheral_role_switch(void) {
  return HCI_SWITCH_SUPPORTED(features_classic[0].as_array);
}

bool supports_enhanced_setup_synchronous_connection(void) {
  return HCI_ENH_SETUP_SYNCH_CONN_SUPPORTED(supported_commands);
}

bool supports_enhanced_accept_synchronous_connection(void) {
  return HCI_ENH_ACCEPT_SYNCH_CONN_SUPPORTED(supported_commands);
}

bool supports_3_slot_packets(void) {
  return HCI_3_SLOT_PACKETS_SUPPORTED(features_classic[0].as_array);
}

bool supports_5_slot_packets(void) {
  return HCI_5_SLOT_PACKETS_SUPPORTED(features_classic[0].as_array);
}

bool supports_classic_2m_phy(void) {
  return HCI_EDR_ACL_2MPS_SUPPORTED(features_classic[0].as_array);
}

bool supports_classic_3m_phy(void) {
  return HCI_EDR_ACL_3MPS_SUPPORTED(features_classic[0].as_array);
}

bool supports_3_slot_edr_packets(void) {
  return HCI_3_SLOT_EDR_ACL_SUPPORTED(features_classic[0].as_array);
}

bool supports_5_slot_edr_packets(void) {
  return HCI_5_SLOT_EDR_ACL_SUPPORTED(features_classic[0].as_array);
}

bool supports_sco(void) {
  return HCI_SCO_LINK_SUPPORTED(features_classic[0].as_array);
}

bool supports_hv2_packets(void) {
  return HCI_HV2_PACKETS_SUPPORTED(features_classic[0].as_array);
}

bool supports_hv3_packets(void) {
  return HCI_HV3_PACKETS_SUPPORTED(features_classic[0].as_array);
}

bool supports_ev3_packets(void) {
  return HCI_ESCO_EV3_SUPPORTED(features_classic[0].as_array);
}

bool supports_ev4_packets(void) {
  return HCI_ESCO_EV4_SUPPORTED(features_classic[0].as_array);
}

bool supports_ev5_packets(void) {
  return HCI_ESCO_EV5_SUPPORTED(features_classic[0].as_array);
}

bool supports_esco_2m_phy(void) {
  return HCI_EDR_ESCO_2MPS_SUPPORTED(features_classic[0].as_array);
}

bool supports_esco_3m_phy(void) {
  return HCI_EDR_ESCO_3MPS_SUPPORTED(features_classic[0].as_array);
}

bool supports_3_slot_esco_edr_packets(void) {
  return HCI_3_SLOT_EDR_ESCO_SUPPORTED(features_classic[0].as_array);
}

bool supports_role_switch(void) {
  return HCI_SWITCH_SUPPORTED(features_classic[0].as_array);
}

bool supports_hold_mode(void) {
  return HCI_HOLD_MODE_SUPPORTED(features_classic[0].as_array);
}

bool supports_sniff_mode(void) {
  return HCI_SNIFF_MODE_SUPPORTED(features_classic[0].as_array);
}

bool supports_park_mode(void) {
  return HCI_PARK_MODE_SUPPORTED(features_classic[0].as_array);
}

bool supports_non_flushable_pb(void) {
  return HCI_NON_FLUSHABLE_PB_SUPPORTED(features_classic[0].as_array);
}

bool supports_sniff_subrating(void) {
  return HCI_SNIFF_SUB_RATE_SUPPORTED(features_classic[0].as_array);
}

bool supports_encryption_pause(void) {
  return HCI_ATOMIC_ENCRYPT_SUPPORTED(features_classic[0].as_array);
}

bool supports_ble(void) { return ble_supported; }

bool supports_ble_privacy(void) {
  return HCI_LE_ENHANCED_PRIVACY_SUPPORTED(features_ble.as_array);
}

bool supports_ble_set_privacy_mode() {
  return HCI_LE_ENHANCED_PRIVACY_SUPPORTED(features_ble.as_array) &&
         HCI_LE_SET_PRIVACY_MODE_SUPPORTED(supported_commands);
}

bool supports_ble_packet_extension(void) {
  return HCI_LE_DATA_LEN_EXT_SUPPORTED(features_ble.as_array);
}

bool supports_ble_connection_parameters_request(void) {
  return HCI_LE_CONN_PARAM_REQ_SUPPORTED(features_ble.as_array);
}

bool supports_ble_2m_phy(void) {
  return HCI_LE_2M_PHY_SUPPORTED(features_ble.as_array);
}

bool supports_ble_coded_phy(void) {
  return HCI_LE_CODED_PHY_SUPPORTED(features_ble.as_array);
}

bool supports_ble_extended_advertising(void) {
  return HCI_LE_EXTENDED_ADVERTISING_SUPPORTED(features_ble.as_array);
}

bool supports_ble_periodic_advertising(void) {
  return HCI_LE_PERIODIC_ADVERTISING_SUPPORTED(features_ble.as_array);
}

bool supports_ble_peripheral_initiated_feature_exchange(void) {
  return HCI_LE_PERIPHERAL_INIT_FEAT_EXC_SUPPORTED(features_ble.as_array);
}

bool supports_ble_connection_parameter_request(void) {
  return HCI_LE_CONN_PARAM_REQ_SUPPORTED(features_ble.as_array);
}

bool supports_ble_periodic_advertising_sync_transfer_sender(void) {
  return HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_SENDER(
      features_ble.as_array);
}

bool supports_ble_periodic_advertising_sync_transfer_recipient(void) {
  return HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECIPIENT(
      features_ble.as_array);
}

bool supports_ble_connected_isochronous_stream_central(void) {
  return HCI_LE_CIS_CENTRAL(features_ble.as_array);
}

bool supports_ble_connected_isochronous_stream_peripheral(void) {
  return HCI_LE_CIS_PERIPHERAL(features_ble.as_array);
}

bool supports_ble_isochronous_broadcaster(void) {
  return HCI_LE_ISO_BROADCASTER(features_ble.as_array);
}

bool supports_ble_synchronized_receiver(void) {
  return HCI_LE_SYNCHRONIZED_RECEIVER(features_ble.as_array);
}

uint16_t get_acl_data_size_classic(void) { return acl_data_size_classic; }

uint16_t get_acl_data_size_ble(void) { return acl_data_size_ble; }

uint16_t get_iso_data_size(void) { return iso_data_size; }

uint16_t get_acl_packet_size_classic(void) {
  return acl_data_size_classic + HCI_DATA_PREAMBLE_SIZE;
}

uint16_t get_acl_packet_size_ble(void) {
  return acl_data_size_ble + HCI_DATA_PREAMBLE_SIZE;
}

uint16_t get_iso_packet_size(void) {
  return iso_data_size + HCI_DATA_PREAMBLE_SIZE;
}

uint16_t get_ble_suggested_default_data_length(void) {
  return ble_suggested_default_data_length;
}

uint16_t get_ble_maximum_tx_data_length(void) {
  return ble_supported_max_tx_octets;
}

uint16_t get_ble_maximum_tx_time(void) { return ble_supported_max_tx_time; }

uint16_t get_ble_maxium_advertising_data_length(void) {
  return ble_maxium_advertising_data_length;
}

uint8_t get_ble_number_of_supported_advertising_sets(void) {
  return ble_number_of_supported_advertising_sets;
}

uint8_t get_ble_periodic_advertiser_list_size(void) {
  return ble_periodic_advertiser_list_size;
}

uint16_t get_acl_buffer_count_classic(void) { return acl_buffer_count_classic; }

uint8_t get_acl_buffer_count_ble(void) { return acl_buffer_count_ble; }

uint8_t get_iso_buffer_count(void) { return iso_buffer_count; }

uint8_t get_ble_acceptlist_size(void) { return ble_acceptlist_size; }

uint8_t get_ble_resolving_list_max_size(void) {
  return ble_resolving_list_max_size;
}

void set_ble_resolving_list_max_size(int resolving_list_max_size) {
  ble_resolving_list_max_size = resolving_list_max_size;
}

uint8_t get_le_all_initiating_phys() {
  uint8_t phy = PHY_LE_1M;
  return phy;
}

const controller_t interface = {
    get_is_ready,

    get_address,
    get_bt_version,

    get_ble_supported_states,

    supports_simple_pairing,
    supports_secure_connections,
    supports_simultaneous_le_bredr,
    supports_reading_remote_extended_features,
    supports_interlaced_inquiry_scan,
    supports_rssi_with_inquiry_results,
    supports_extended_inquiry_response,
    supports_central_peripheral_role_switch,
    supports_enhanced_setup_synchronous_connection,
    supports_enhanced_accept_synchronous_connection,
    supports_3_slot_packets,
    supports_5_slot_packets,
    supports_classic_2m_phy,
    supports_classic_3m_phy,
    supports_3_slot_edr_packets,
    supports_5_slot_edr_packets,
    supports_sco,
    supports_hv2_packets,
    supports_hv3_packets,
    supports_ev3_packets,
    supports_ev4_packets,
    supports_ev5_packets,
    supports_esco_2m_phy,
    supports_esco_3m_phy,
    supports_3_slot_esco_edr_packets,
    supports_role_switch,
    supports_hold_mode,
    supports_sniff_mode,
    supports_park_mode,
    supports_non_flushable_pb,
    supports_sniff_subrating,
    supports_encryption_pause,

    supports_ble,
    supports_ble_packet_extension,
    supports_ble_connection_parameters_request,
    supports_ble_privacy,
    supports_ble_set_privacy_mode,
    supports_ble_2m_phy,
    supports_ble_coded_phy,
    supports_ble_extended_advertising,
    supports_ble_periodic_advertising,
    supports_ble_peripheral_initiated_feature_exchange,
    supports_ble_connection_parameter_request,
    supports_ble_periodic_advertising_sync_transfer_sender,
    supports_ble_periodic_advertising_sync_transfer_recipient,
    supports_ble_connected_isochronous_stream_central,
    supports_ble_connected_isochronous_stream_peripheral,
    supports_ble_isochronous_broadcaster,
    supports_ble_synchronized_receiver,

    get_acl_data_size_classic,
    get_acl_data_size_ble,
    get_iso_data_size,

    get_acl_packet_size_classic,
    get_acl_packet_size_ble,
    get_iso_packet_size,

    get_ble_suggested_default_data_length,
    get_ble_maximum_tx_data_length,
    get_ble_maximum_tx_time,
    get_ble_maxium_advertising_data_length,
    get_ble_number_of_supported_advertising_sets,
    get_ble_periodic_advertiser_list_size,

    get_acl_buffer_count_classic,
    get_acl_buffer_count_ble,
    get_iso_buffer_count,

    get_ble_acceptlist_size,

    get_ble_resolving_list_max_size,
    set_ble_resolving_list_max_size,
    get_local_supported_codecs,
    get_le_all_initiating_phys};

}  // namespace device_controller
}  // namespace mock
}  // namespace test

// Mocked functions, if any
const controller_t* controller_get_interface() {
  return &test::mock::device_controller::interface;
}

// END mockcify generation
