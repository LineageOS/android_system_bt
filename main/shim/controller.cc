/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "bt_shim_controller"

#include "main/shim/controller.h"
#include "btcore/include/module.h"
#include "main/shim/entry.h"
#include "main/shim/shim.h"
#include "osi/include/future.h"
#include "osi/include/log.h"

#include "hci/controller.h"

using ::bluetooth::shim::GetController;

constexpr uint8_t kMaxFeaturePage = 3;

constexpr int kMaxSupportedCodecs = 8;  // MAX_LOCAL_SUPPORTED_CODECS_SIZE

constexpr uint8_t kPhyLe1M = 0x01;

/**
 * Interesting commands supported by controller
 */
constexpr int kReadRemoteExtendedFeatures = 0x41c;
constexpr int kEnhancedSetupSynchronousConnection = 0x428;
constexpr int kEnhancedAcceptSynchronousConnection = 0x429;
constexpr int kLeSetPrivacyMode = 0x204e;

constexpr int kHciDataPreambleSize = 4;  // #define HCI_DATA_PREAMBLE_SIZE 4

// Module lifecycle functions
static future_t* start_up(void);
static future_t* shut_down(void);

EXPORT_SYMBOL extern const module_t gd_controller_module = {
    .name = GD_CONTROLLER_MODULE,
    .init = nullptr,
    .start_up = start_up,
    .shut_down = shut_down,
    .clean_up = nullptr,
    .dependencies = {GD_SHIM_MODULE, nullptr}};

struct {
  bool ready;
  uint64_t feature[kMaxFeaturePage];
  uint64_t le_feature[kMaxFeaturePage];
  RawAddress raw_address;
  bt_version_t bt_version;
  uint8_t local_supported_codecs[kMaxSupportedCodecs];
  uint8_t number_of_local_supported_codecs;
  uint64_t le_supported_states;
  uint8_t phy;
} data_;

static future_t* start_up(void) {
  LOG_INFO("%s Starting up", __func__);
  data_.ready = true;

  std::string string_address = GetController()->GetMacAddress().ToString();
  RawAddress::FromString(string_address, data_.raw_address);

  data_.le_supported_states =
      bluetooth::shim::GetController()->GetLeSupportedStates();

  LOG_INFO("Mac address:%s", string_address.c_str());

  data_.phy = kPhyLe1M;

  return future_new_immediate(FUTURE_SUCCESS);
}

static future_t* shut_down(void) {
  data_.ready = false;
  return future_new_immediate(FUTURE_SUCCESS);
}

/**
 * Module methods
 */

static bool get_is_ready(void) { return data_.ready; }

static const RawAddress* get_address(void) { return &data_.raw_address; }

static const bt_version_t* get_bt_version(void) { return &data_.bt_version; }

static uint8_t* get_local_supported_codecs(uint8_t* number_of_codecs) {
  CHECK(number_of_codecs != nullptr);
  if (data_.number_of_local_supported_codecs != 0) {
    *number_of_codecs = data_.number_of_local_supported_codecs;
    return data_.local_supported_codecs;
  }
  return (uint8_t*)nullptr;
}

static const uint8_t* get_ble_supported_states(void) {
  return (const uint8_t*)&data_.le_supported_states;
}

#define MAP_TO_GD(legacy, gd) \
  static bool legacy(void) { return GetController()->gd(); }

MAP_TO_GD(supports_simple_pairing, SupportsSimplePairing)
MAP_TO_GD(supports_secure_connections, SupportsSecureConnections)
MAP_TO_GD(supports_simultaneous_le_bredr, SupportsSimultaneousLeBrEdr)
MAP_TO_GD(supports_interlaced_inquiry_scan, SupportsInterlacedInquiryScan)
MAP_TO_GD(supports_rssi_with_inquiry_results, SupportsRssiWithInquiryResults)
MAP_TO_GD(supports_extended_inquiry_response, SupportsExtendedInquiryResponse)
MAP_TO_GD(supports_master_slave_role_switch, SupportsRoleSwitch)
MAP_TO_GD(supports_3_slot_packets, Supports3SlotPackets)
MAP_TO_GD(supports_5_slot_packets, Supports5SlotPackets)
MAP_TO_GD(supports_classic_2m_phy, SupportsClassic2mPhy)
MAP_TO_GD(supports_classic_3m_phy, SupportsClassic3mPhy)
MAP_TO_GD(supports_3_slot_edr_packets, Supports3SlotEdrPackets)
MAP_TO_GD(supports_5_slot_edr_packets, Supports5SlotEdrPackets)
MAP_TO_GD(supports_sco, SupportsSco)
MAP_TO_GD(supports_hv2_packets, SupportsHv2Packets)
MAP_TO_GD(supports_hv3_packets, SupportsHv3Packets)
MAP_TO_GD(supports_ev3_packets, SupportsEv3Packets)
MAP_TO_GD(supports_ev4_packets, SupportsEv4Packets)
MAP_TO_GD(supports_ev5_packets, SupportsEv5Packets)
MAP_TO_GD(supports_esco_2m_phy, SupportsEsco2mPhy)
MAP_TO_GD(supports_esco_3m_phy, SupportsEsco3mPhy)
MAP_TO_GD(supports_3_slot_esco_edr_packets, Supports3SlotEscoEdrPackets)
MAP_TO_GD(supports_role_switch, SupportsRoleSwitch)
MAP_TO_GD(supports_hold_mode, SupportsHoldMode)
MAP_TO_GD(supports_sniff_mode, SupportsSniffMode)
MAP_TO_GD(supports_park_mode, SupportsParkMode)
MAP_TO_GD(supports_non_flushable_pb, SupportsNonFlushablePb)
MAP_TO_GD(supports_sniff_subrating, SupportsSniffSubrating)
MAP_TO_GD(supports_encryption_pause, SupportsEncryptionPause)

MAP_TO_GD(supports_ble, SupportsBle)
MAP_TO_GD(supports_ble_privacy, SupportsBlePrivacy)
MAP_TO_GD(supports_ble_packet_extension, SupportsBlePacketExtension)
MAP_TO_GD(supports_ble_connection_parameters_request,
          SupportsBleConnectionParametersRequest)
MAP_TO_GD(supports_ble_2m_phy, SupportsBle2mPhy)
MAP_TO_GD(supports_ble_coded_phy, SupportsBleCodedPhy)
MAP_TO_GD(supports_ble_extended_advertising, SupportsBleExtendedAdvertising)
MAP_TO_GD(supports_ble_periodic_advertising, SupportsBlePeriodicAdvertising)
MAP_TO_GD(supports_ble_peripheral_initiated_feature_exchange,
          SupportsBlePeripheralInitiatedFeatureExchange)
MAP_TO_GD(supports_ble_connection_parameter_request,
          SupportsBleConnectionParameterRequest)

MAP_TO_GD(supports_ble_periodic_advertising_sync_transfer_sender,
          SupportsBlePeriodicAdvertisingSyncTransferSender)
MAP_TO_GD(supports_ble_periodic_advertising_sync_transfer_recipient,
          SupportsBlePeriodicAdvertisingSyncTransferRecipient)
MAP_TO_GD(supports_ble_connected_isochronous_stream_master,
          SupportsBleConnectedIsochronousStreamMaster)
MAP_TO_GD(supports_ble_connected_isochronous_stream_slave,
          SupportsBleConnectedIsochronousStreamSlave)
MAP_TO_GD(supports_ble_isochronous_broadcaster,
          SupportsBleIsochronousBroadcaster)
MAP_TO_GD(supports_ble_synchronized_receiver, SupportsBleSynchronizedReceiver)

static bool supports_reading_remote_extended_features(void) {
  return GetController()->IsSupported(
      (bluetooth::hci::OpCode)kReadRemoteExtendedFeatures);
}

static bool supports_enhanced_setup_synchronous_connection(void) {
  return GetController()->IsSupported(
      (bluetooth::hci::OpCode)kEnhancedSetupSynchronousConnection);
}

static bool supports_enhanced_accept_synchronous_connection(void) {
  return GetController()->IsSupported(
      (bluetooth::hci::OpCode)kEnhancedAcceptSynchronousConnection);
}

static bool supports_ble_set_privacy_mode() {
  return GetController()->IsSupported(
      (bluetooth::hci::OpCode)kLeSetPrivacyMode);
}

static uint16_t get_acl_data_size_classic(void) {
  return GetController()->GetAclPacketLength();
}

static uint16_t get_acl_data_size_ble(void) {
  return GetController()->GetLeBufferSize().le_data_packet_length_;
}

static uint16_t get_iso_data_size(void) {
  return GetController()->GetControllerIsoBufferSize().le_data_packet_length_;
}

static uint16_t get_acl_packet_size_classic(void) {
  return get_acl_data_size_classic() + kHciDataPreambleSize;
}

static uint16_t get_acl_packet_size_ble(void) {
  return get_acl_data_size_ble() + kHciDataPreambleSize;
}

static uint16_t get_iso_packet_size(void) {
  return get_iso_data_size() + kHciDataPreambleSize;
}

static uint16_t get_ble_suggested_default_data_length(void) {
  return GetController()->GetLeSuggestedDefaultDataLength();
}

static uint16_t get_ble_maximum_tx_data_length(void) {
  ::bluetooth::hci::LeMaximumDataLength le_maximum_data_length =
      GetController()->GetLeMaximumDataLength();
  return le_maximum_data_length.supported_max_tx_octets_;
}

static uint16_t get_ble_maxium_advertising_data_length(void) {
  return GetController()->GetLeMaximumAdvertisingDataLength();
}

static uint8_t get_ble_number_of_supported_advertising_sets(void) {
  return GetController()->GetLeNumberOfSupportedAdverisingSets();
}

static uint8_t get_ble_periodic_advertiser_list_size(void) {
  return GetController()->GetLePeriodicAdvertiserListSize();
}

static uint16_t get_acl_buffer_count_classic(void) {
  return GetController()->GetNumAclPacketBuffers();
}

static uint8_t get_acl_buffer_count_ble(void) {
  return GetController()->GetLeBufferSize().total_num_le_packets_;
}

static uint8_t get_iso_buffer_count(void) {
  return GetController()->GetControllerIsoBufferSize().total_num_le_packets_;
}

static uint8_t get_ble_connect_list_size(void) {
  return GetController()->GetLeConnectListSize();
}

static uint8_t get_ble_resolving_list_max_size(void) {
  return GetController()->GetLeResolvingListSize();
}

static void set_ble_resolving_list_max_size(int resolving_list_max_size) {
  LOG_WARN("%s TODO Unimplemented", __func__);
}

static uint8_t get_le_all_initiating_phys() { return data_.phy; }

static const controller_t interface = {
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
    supports_master_slave_role_switch,
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
    supports_ble_connected_isochronous_stream_master,
    supports_ble_connected_isochronous_stream_slave,
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
    get_ble_maxium_advertising_data_length,
    get_ble_number_of_supported_advertising_sets,
    get_ble_periodic_advertiser_list_size,

    get_acl_buffer_count_classic,
    get_acl_buffer_count_ble,
    get_iso_buffer_count,

    get_ble_connect_list_size,

    get_ble_resolving_list_max_size,
    set_ble_resolving_list_max_size,
    get_local_supported_codecs,
    get_le_all_initiating_phys};

const controller_t* bluetooth::shim::controller_get_interface() {
  static bool loaded = false;
  if (!loaded) {
    loaded = true;
  }
  return &interface;
}
