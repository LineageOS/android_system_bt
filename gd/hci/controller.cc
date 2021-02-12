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

#include "hci/controller.h"

#include <future>
#include <memory>
#include <string>
#include <utility>

#include "common/init_flags.h"
#include "hci/hci_layer.h"

namespace bluetooth {
namespace hci {

using os::Handler;

struct Controller::impl {
  impl(Controller& module) : module_(module) {}

  void Start(hci::HciLayer* hci) {
    hci_ = hci;
    Handler* handler = module_.GetHandler();
    if (common::init_flags::gd_acl_is_enabled() || common::init_flags::gd_l2cap_is_enabled()) {
      hci_->RegisterEventHandler(
          EventCode::NUMBER_OF_COMPLETED_PACKETS, handler->BindOn(this, &Controller::impl::NumberOfCompletedPackets));
    }

    le_set_event_mask(kDefaultLeEventMask);
    set_event_mask(kDefaultEventMask);
    write_le_host_support(Enable::ENABLED);
    // SSP is managed by security layer once enabled
    if (!common::init_flags::gd_security_is_enabled()) {
      write_simple_pairing_mode(Enable::ENABLED);
    }
    hci_->EnqueueCommand(ReadLocalNameBuilder::Create(),
                         handler->BindOnceOn(this, &Controller::impl::read_local_name_complete_handler));
    hci_->EnqueueCommand(ReadLocalVersionInformationBuilder::Create(),
                         handler->BindOnceOn(this, &Controller::impl::read_local_version_information_complete_handler));
    hci_->EnqueueCommand(ReadLocalSupportedCommandsBuilder::Create(),
                         handler->BindOnceOn(this, &Controller::impl::read_local_supported_commands_complete_handler));

    // Wait for all extended features read
    std::promise<void> features_promise;
    auto features_future = features_promise.get_future();
    hci_->EnqueueCommand(ReadLocalExtendedFeaturesBuilder::Create(0x00),
                         handler->BindOnceOn(this, &Controller::impl::read_local_extended_features_complete_handler,
                                             std::move(features_promise)));
    features_future.wait();

    hci_->EnqueueCommand(ReadBufferSizeBuilder::Create(),
                         handler->BindOnceOn(this, &Controller::impl::read_buffer_size_complete_handler));

    if (is_supported(OpCode::LE_READ_BUFFER_SIZE_V2)) {
      hci_->EnqueueCommand(
          LeReadBufferSizeV2Builder::Create(),
          handler->BindOnceOn(this, &Controller::impl::le_read_buffer_size_v2_handler));
    } else {
      hci_->EnqueueCommand(
          LeReadBufferSizeV1Builder::Create(),
          handler->BindOnceOn(this, &Controller::impl::le_read_buffer_size_handler));
    }

    hci_->EnqueueCommand(LeReadLocalSupportedFeaturesBuilder::Create(),
                         handler->BindOnceOn(this, &Controller::impl::le_read_local_supported_features_handler));

    hci_->EnqueueCommand(LeReadSupportedStatesBuilder::Create(),
                         handler->BindOnceOn(this, &Controller::impl::le_read_supported_states_handler));

    hci_->EnqueueCommand(
        LeReadConnectListSizeBuilder::Create(),
        handler->BindOnceOn(this, &Controller::impl::le_read_connect_list_size_handler));

    hci_->EnqueueCommand(
        LeReadResolvingListSizeBuilder::Create(),
        handler->BindOnceOn(this, &Controller::impl::le_read_resolving_list_size_handler));

    if (is_supported(OpCode::LE_READ_MAXIMUM_DATA_LENGTH)) {
      hci_->EnqueueCommand(LeReadMaximumDataLengthBuilder::Create(),
                           handler->BindOnceOn(this, &Controller::impl::le_read_maximum_data_length_handler));
    } else {
      le_maximum_data_length_.supported_max_rx_octets_ = 0;
      le_maximum_data_length_.supported_max_rx_time_ = 0;
      le_maximum_data_length_.supported_max_tx_octets_ = 0;
      le_maximum_data_length_.supported_max_tx_time_ = 0;
    }
    if (is_supported(OpCode::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH)) {
      hci_->EnqueueCommand(
          LeReadSuggestedDefaultDataLengthBuilder::Create(),
          handler->BindOnceOn(this, &Controller::impl::le_read_suggested_default_data_length_handler));
    }
    if (is_supported(OpCode::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH)) {
      hci_->EnqueueCommand(
          LeReadMaximumAdvertisingDataLengthBuilder::Create(),
          handler->BindOnceOn(this, &Controller::impl::le_read_maximum_advertising_data_length_handler));
    } else {
      le_maximum_advertising_data_length_ = 31;
    }
    if (is_supported(OpCode::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS)) {
      hci_->EnqueueCommand(
          LeReadNumberOfSupportedAdvertisingSetsBuilder::Create(),
          handler->BindOnceOn(this, &Controller::impl::le_read_number_of_supported_advertising_sets_handler));
    } else {
      le_number_supported_advertising_sets_ = 1;
    }
    if (is_supported(OpCode::LE_READ_PERIODIC_ADVERTISING_LIST_SIZE)) {
      hci_->EnqueueCommand(
          LeReadPeriodicAdvertiserListSizeBuilder::Create(),
          handler->BindOnceOn(this, &Controller::impl::le_read_periodic_advertiser_list_size_handler));
    }

    hci_->EnqueueCommand(LeGetVendorCapabilitiesBuilder::Create(),
                         handler->BindOnceOn(this, &Controller::impl::le_get_vendor_capabilities_handler));

    // We only need to synchronize the last read. Make BD_ADDR to be the last one.
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_->EnqueueCommand(
        ReadBdAddrBuilder::Create(),
        handler->BindOnceOn(this, &Controller::impl::read_controller_mac_address_handler, std::move(promise)));
    future.wait();
  }

  void Stop() {
    if (bluetooth::common::init_flags::gd_core_is_enabled()) {
      hci_->UnregisterEventHandler(EventCode::NUMBER_OF_COMPLETED_PACKETS);
    }
    hci_ = nullptr;
  }

  void NumberOfCompletedPackets(EventView event) {
    if (acl_credits_callback_.IsEmpty()) {
      LOG_WARN("Received event when AclManager is not listening");
      return;
    }
    auto complete_view = NumberOfCompletedPacketsView::Create(event);
    ASSERT(complete_view.IsValid());
    for (auto completed_packets : complete_view.GetCompletedPackets()) {
      uint16_t handle = completed_packets.connection_handle_;
      uint16_t credits = completed_packets.host_num_of_completed_packets_;
      acl_credits_callback_.Invoke(handle, credits);
      if (!acl_monitor_credits_callback_.IsEmpty()) {
        acl_monitor_credits_callback_.Invoke(handle, credits);
      }
    }
  }

  void register_completed_acl_packets_callback(CompletedAclPacketsCallback callback) {
    ASSERT(acl_credits_callback_.IsEmpty());
    acl_credits_callback_ = callback;
  }

  void unregister_completed_acl_packets_callback() {
    ASSERT(!acl_credits_callback_.IsEmpty());
    acl_credits_callback_ = {};
  }

  void register_completed_monitor_acl_packets_callback(CompletedAclPacketsCallback callback) {
    ASSERT(acl_monitor_credits_callback_.IsEmpty());
    acl_monitor_credits_callback_ = callback;
  }

  void unregister_completed_monitor_acl_packets_callback() {
    ASSERT(!acl_monitor_credits_callback_.IsEmpty());
    acl_monitor_credits_callback_ = {};
  }

  void register_monitor_completed_acl_packets_callback(CompletedAclPacketsCallback callback) {
    ASSERT(acl_monitor_credits_callback_.IsEmpty());
    acl_monitor_credits_callback_ = callback;
  }

  void unregister_monitor_completed_acl_packets_callback() {
    ASSERT(!acl_monitor_credits_callback_.IsEmpty());
    acl_monitor_credits_callback_ = {};
  }

  void read_local_name_complete_handler(CommandCompleteView view) {
    auto complete_view = ReadLocalNameCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    std::array<uint8_t, 248> local_name_array = complete_view.GetLocalName();

    local_name_ = std::string(local_name_array.begin(), local_name_array.end());
    // erase \0
    local_name_.erase(std::find(local_name_.begin(), local_name_.end(), '\0'), local_name_.end());
  }

  void read_local_version_information_complete_handler(CommandCompleteView view) {
    auto complete_view = ReadLocalVersionInformationCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());

    local_version_information_ = complete_view.GetLocalVersionInformation();
  }

  void read_local_supported_commands_complete_handler(CommandCompleteView view) {
    auto complete_view = ReadLocalSupportedCommandsCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    local_supported_commands_ = complete_view.GetSupportedCommands();
  }

  void read_local_extended_features_complete_handler(std::promise<void> promise, CommandCompleteView view) {
    auto complete_view = ReadLocalExtendedFeaturesCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    uint8_t page_number = complete_view.GetPageNumber();
    maximum_page_number_ = complete_view.GetMaximumPageNumber();
    extended_lmp_features_array_.push_back(complete_view.GetExtendedLmpFeatures());

    // Query all extended features
    if (page_number < maximum_page_number_) {
      page_number++;
      hci_->EnqueueCommand(
          ReadLocalExtendedFeaturesBuilder::Create(page_number),
          module_.GetHandler()->BindOnceOn(this, &Controller::impl::read_local_extended_features_complete_handler,
                                           std::move(promise)));
    } else {
      promise.set_value();
    }
  }

  void read_buffer_size_complete_handler(CommandCompleteView view) {
    auto complete_view = ReadBufferSizeCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    acl_buffer_length_ = complete_view.GetAclDataPacketLength();
    acl_buffers_ = complete_view.GetTotalNumAclDataPackets();

    sco_buffer_length_ = complete_view.GetSynchronousDataPacketLength();
    sco_buffers_ = complete_view.GetTotalNumSynchronousDataPackets();
  }

  void read_controller_mac_address_handler(std::promise<void> promise, CommandCompleteView view) {
    auto complete_view = ReadBdAddrCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    mac_address_ = complete_view.GetBdAddr();
    promise.set_value();
  }

  void le_read_buffer_size_handler(CommandCompleteView view) {
    auto complete_view = LeReadBufferSizeV1CompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_buffer_size_ = complete_view.GetLeBufferSize();

    // If LE buffer size is zero, then buffers returned by Read_Buffer_Size are shared between BR/EDR and LE.
    if (le_buffer_size_.total_num_le_packets_ == 0) {
      ASSERT(acl_buffers_ != 0);
      le_buffer_size_.total_num_le_packets_ = acl_buffers_ / 2;
      acl_buffers_ -= le_buffer_size_.total_num_le_packets_;
      le_buffer_size_.le_data_packet_length_ = acl_buffer_length_;
    }
  }

  void le_read_buffer_size_v2_handler(CommandCompleteView view) {
    auto complete_view = LeReadBufferSizeV2CompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_buffer_size_ = complete_view.GetLeBufferSize();
    iso_buffer_size_ = complete_view.GetIsoBufferSize();

    // If LE buffer size is zero, then buffers returned by Read_Buffer_Size are shared between BR/EDR and LE.
    if (le_buffer_size_.total_num_le_packets_ == 0) {
      ASSERT(acl_buffers_ != 0);
      le_buffer_size_.total_num_le_packets_ = acl_buffers_ / 2;
      acl_buffers_ -= le_buffer_size_.total_num_le_packets_;
      le_buffer_size_.le_data_packet_length_ = acl_buffer_length_;
    }
  }

  void le_read_local_supported_features_handler(CommandCompleteView view) {
    auto complete_view = LeReadLocalSupportedFeaturesCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_local_supported_features_ = complete_view.GetLeFeatures();
  }

  void le_read_supported_states_handler(CommandCompleteView view) {
    auto complete_view = LeReadSupportedStatesCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_supported_states_ = complete_view.GetLeStates();
  }

  void le_read_connect_list_size_handler(CommandCompleteView view) {
    auto complete_view = LeReadConnectListSizeCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_connect_list_size_ = complete_view.GetConnectListSize();
  }

  void le_read_resolving_list_size_handler(CommandCompleteView view) {
    auto complete_view = LeReadResolvingListSizeCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_resolving_list_size_ = complete_view.GetResolvingListSize();
  }

  void le_read_maximum_data_length_handler(CommandCompleteView view) {
    auto complete_view = LeReadMaximumDataLengthCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_maximum_data_length_ = complete_view.GetLeMaximumDataLength();
  }

  void le_read_suggested_default_data_length_handler(CommandCompleteView view) {
    auto complete_view = LeReadSuggestedDefaultDataLengthCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_suggested_default_data_length_ = complete_view.GetTxOctets();
  }

  void le_read_maximum_advertising_data_length_handler(CommandCompleteView view) {
    auto complete_view = LeReadMaximumAdvertisingDataLengthCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_maximum_advertising_data_length_ = complete_view.GetMaximumAdvertisingDataLength();
  }

  void le_read_number_of_supported_advertising_sets_handler(CommandCompleteView view) {
    auto complete_view = LeReadNumberOfSupportedAdvertisingSetsCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_number_supported_advertising_sets_ = complete_view.GetNumberSupportedAdvertisingSets();
  }

  void le_read_periodic_advertiser_list_size_handler(CommandCompleteView view) {
    auto complete_view = LeReadPeriodicAdvertiserListSizeCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_periodic_advertiser_list_size_ = complete_view.GetPeriodicAdvertiserListSize();
  }

  void le_get_vendor_capabilities_handler(CommandCompleteView view) {
    auto complete_view = LeGetVendorCapabilitiesCompleteView::Create(view);

    vendor_capabilities_.is_supported_ = 0x00;
    vendor_capabilities_.max_advt_instances_ = 0x00;
    vendor_capabilities_.offloaded_resolution_of_private_address_ = 0x00;
    vendor_capabilities_.total_scan_results_storage_ = 0x00;
    vendor_capabilities_.max_irk_list_sz_ = 0x00;
    vendor_capabilities_.filtering_support_ = 0x00;
    vendor_capabilities_.max_filter_ = 0x00;
    vendor_capabilities_.activity_energy_info_support_ = 0x00;
    vendor_capabilities_.version_supported_ = 0x00;
    vendor_capabilities_.version_supported_ = 0x00;
    vendor_capabilities_.total_num_of_advt_tracked_ = 0x00;
    vendor_capabilities_.extended_scan_support_ = 0x00;
    vendor_capabilities_.debug_logging_supported_ = 0x00;
    vendor_capabilities_.le_address_generation_offloading_support_ = 0x00;
    vendor_capabilities_.a2dp_source_offload_capability_mask_ = 0x00;
    vendor_capabilities_.bluetooth_quality_report_support_ = 0x00;

    if (complete_view.IsValid()) {
      vendor_capabilities_.is_supported_ = 0x01;

      // v0.55
      BaseVendorCapabilities base_vendor_capabilities = complete_view.GetBaseVendorCapabilities();
      vendor_capabilities_.max_advt_instances_ = base_vendor_capabilities.max_advt_instances_;
      vendor_capabilities_.offloaded_resolution_of_private_address_ =
          base_vendor_capabilities.offloaded_resolution_of_private_address_;
      vendor_capabilities_.total_scan_results_storage_ = base_vendor_capabilities.total_scan_results_storage_;
      vendor_capabilities_.max_irk_list_sz_ = base_vendor_capabilities.max_irk_list_sz_;
      vendor_capabilities_.filtering_support_ = base_vendor_capabilities.filtering_support_;
      vendor_capabilities_.max_filter_ = base_vendor_capabilities.max_filter_;
      vendor_capabilities_.activity_energy_info_support_ = base_vendor_capabilities.activity_energy_info_support_;
      if (complete_view.GetPayload().size() == 0) {
        vendor_capabilities_.version_supported_ = 55;
        return;
      }

      // v0.95
      auto v95 = LeGetVendorCapabilitiesComplete095View::Create(complete_view);
      if (!v95.IsValid()) {
        LOG_ERROR("invalid data for hci requirements v0.95");
        return;
      }
      vendor_capabilities_.version_supported_ = v95.GetVersionSupported();
      vendor_capabilities_.total_num_of_advt_tracked_ = v95.GetTotalNumOfAdvtTracked();
      vendor_capabilities_.extended_scan_support_ = v95.GetExtendedScanSupport();
      vendor_capabilities_.debug_logging_supported_ = v95.GetDebugLoggingSupported();
      if (vendor_capabilities_.version_supported_ <= 95 || complete_view.GetPayload().size() == 0) {
        return;
      }

      // v0.96
      auto v96 = LeGetVendorCapabilitiesComplete096View::Create(v95);
      if (!v96.IsValid()) {
        LOG_ERROR("invalid data for hci requirements v0.96");
        return;
      }
      vendor_capabilities_.le_address_generation_offloading_support_ = v96.GetLeAddressGenerationOffloadingSupport();
      if (vendor_capabilities_.version_supported_ <= 96 || complete_view.GetPayload().size() == 0) {
        return;
      }

      // v0.98
      auto v98 = LeGetVendorCapabilitiesComplete098View::Create(v96);
      if (!v98.IsValid()) {
        LOG_ERROR("invalid data for hci requirements v0.98");
        return;
      }
      vendor_capabilities_.a2dp_source_offload_capability_mask_ = v98.GetA2dpSourceOffloadCapabilityMask();
      vendor_capabilities_.bluetooth_quality_report_support_ = v98.GetBluetoothQualityReportSupport();
    }
  }

  void set_event_mask(uint64_t event_mask) {
    std::unique_ptr<SetEventMaskBuilder> packet = SetEventMaskBuilder::Create(event_mask);
    hci_->EnqueueCommand(std::move(packet), module_.GetHandler()->BindOnceOn(
                                                this, &Controller::impl::check_status<SetEventMaskCompleteView>));
  }

  void write_le_host_support(Enable enable) {
    // Since Bluetooth Core Spec 4.1, this bit should be 0, but some controllers still require it
    Enable simultaneous_le_host = Enable::ENABLED;
    std::unique_ptr<WriteLeHostSupportBuilder> packet = WriteLeHostSupportBuilder::Create(enable, simultaneous_le_host);
    hci_->EnqueueCommand(
        std::move(packet),
        module_.GetHandler()->BindOnceOn(this, &Controller::impl::check_status<WriteLeHostSupportCompleteView>));
  }

  void write_simple_pairing_mode(Enable enable) {
    std::unique_ptr<WriteSimplePairingModeBuilder> packet = WriteSimplePairingModeBuilder::Create(enable);
    hci_->EnqueueCommand(
        std::move(packet),
        module_.GetHandler()->BindOnceOn(this, &Controller::impl::check_status<WriteSimplePairingModeCompleteView>));
  }

  void reset() {
    std::unique_ptr<ResetBuilder> packet = ResetBuilder::Create();
    hci_->EnqueueCommand(std::move(packet),
                         module_.GetHandler()->BindOnceOn(this, &Controller::impl::check_status<ResetCompleteView>));
  }

  void set_event_filter(std::unique_ptr<SetEventFilterBuilder> packet) {
    hci_->EnqueueCommand(std::move(packet), module_.GetHandler()->BindOnceOn(
                                                this, &Controller::impl::check_status<SetEventFilterCompleteView>));
  }

  void write_local_name(std::string local_name) {
    ASSERT(local_name.length() <= 248);
    // Fill remaining char with 0
    local_name.append(std::string(248 - local_name.length(), '\0'));
    std::array<uint8_t, 248> local_name_array;
    std::copy(std::begin(local_name), std::end(local_name), std::begin(local_name_array));

    std::unique_ptr<WriteLocalNameBuilder> packet = WriteLocalNameBuilder::Create(local_name_array);
    hci_->EnqueueCommand(std::move(packet), module_.GetHandler()->BindOnceOn(
                                                this, &Controller::impl::check_status<WriteLocalNameCompleteView>));
  }

  void host_buffer_size(uint16_t host_acl_data_packet_length, uint8_t host_synchronous_data_packet_length,
                        uint16_t host_total_num_acl_data_packets, uint16_t host_total_num_synchronous_data_packets) {
    std::unique_ptr<HostBufferSizeBuilder> packet =
        HostBufferSizeBuilder::Create(host_acl_data_packet_length, host_synchronous_data_packet_length,
                                      host_total_num_acl_data_packets, host_total_num_synchronous_data_packets);
    hci_->EnqueueCommand(std::move(packet), module_.GetHandler()->BindOnceOn(
                                                this, &Controller::impl::check_status<HostBufferSizeCompleteView>));
  }

  void le_set_event_mask(uint64_t le_event_mask) {
    std::unique_ptr<LeSetEventMaskBuilder> packet = LeSetEventMaskBuilder::Create(le_event_mask);
    hci_->EnqueueCommand(std::move(packet), module_.GetHandler()->BindOnceOn(
                                                this, &Controller::impl::check_status<LeSetEventMaskCompleteView>));
  }

  template <class T>
  void check_status(CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto status_view = T::Create(view);
    ASSERT(status_view.IsValid());
    ASSERT(status_view.GetStatus() == ErrorCode::SUCCESS);
  }

#define OP_CODE_MAPPING(name)                                                  \
  case OpCode::name: {                                                         \
    uint16_t index = (uint16_t)OpCodeIndex::name;                              \
    uint16_t byte_index = index / 10;                                          \
    uint16_t bit_index = index % 10;                                           \
    bool supported = local_supported_commands_[byte_index] & (1 << bit_index); \
    if (!supported) {                                                          \
      LOG_WARN("unsupported command opcode: 0x%04x", (uint16_t)OpCode::name);  \
    }                                                                          \
    return supported;                                                          \
  }

  bool is_supported(OpCode op_code) {
    switch (op_code) {
      OP_CODE_MAPPING(INQUIRY)
      OP_CODE_MAPPING(INQUIRY_CANCEL)
      OP_CODE_MAPPING(PERIODIC_INQUIRY_MODE)
      OP_CODE_MAPPING(EXIT_PERIODIC_INQUIRY_MODE)
      OP_CODE_MAPPING(CREATE_CONNECTION)
      OP_CODE_MAPPING(DISCONNECT)
      OP_CODE_MAPPING(CREATE_CONNECTION_CANCEL)
      OP_CODE_MAPPING(ACCEPT_CONNECTION_REQUEST)
      OP_CODE_MAPPING(REJECT_CONNECTION_REQUEST)
      OP_CODE_MAPPING(LINK_KEY_REQUEST_REPLY)
      OP_CODE_MAPPING(LINK_KEY_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(PIN_CODE_REQUEST_REPLY)
      OP_CODE_MAPPING(PIN_CODE_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(CHANGE_CONNECTION_PACKET_TYPE)
      OP_CODE_MAPPING(AUTHENTICATION_REQUESTED)
      OP_CODE_MAPPING(SET_CONNECTION_ENCRYPTION)
      OP_CODE_MAPPING(CHANGE_CONNECTION_LINK_KEY)
      OP_CODE_MAPPING(CENTRAL_LINK_KEY)
      OP_CODE_MAPPING(REMOTE_NAME_REQUEST)
      OP_CODE_MAPPING(REMOTE_NAME_REQUEST_CANCEL)
      OP_CODE_MAPPING(READ_REMOTE_SUPPORTED_FEATURES)
      OP_CODE_MAPPING(READ_REMOTE_EXTENDED_FEATURES)
      OP_CODE_MAPPING(READ_REMOTE_VERSION_INFORMATION)
      OP_CODE_MAPPING(READ_CLOCK_OFFSET)
      OP_CODE_MAPPING(READ_LMP_HANDLE)
      OP_CODE_MAPPING(HOLD_MODE)
      OP_CODE_MAPPING(SNIFF_MODE)
      OP_CODE_MAPPING(EXIT_SNIFF_MODE)
      OP_CODE_MAPPING(QOS_SETUP)
      OP_CODE_MAPPING(ROLE_DISCOVERY)
      OP_CODE_MAPPING(SWITCH_ROLE)
      OP_CODE_MAPPING(READ_LINK_POLICY_SETTINGS)
      OP_CODE_MAPPING(WRITE_LINK_POLICY_SETTINGS)
      OP_CODE_MAPPING(READ_DEFAULT_LINK_POLICY_SETTINGS)
      OP_CODE_MAPPING(WRITE_DEFAULT_LINK_POLICY_SETTINGS)
      OP_CODE_MAPPING(FLOW_SPECIFICATION)
      OP_CODE_MAPPING(SET_EVENT_MASK)
      OP_CODE_MAPPING(RESET)
      OP_CODE_MAPPING(SET_EVENT_FILTER)
      OP_CODE_MAPPING(FLUSH)
      OP_CODE_MAPPING(READ_PIN_TYPE)
      OP_CODE_MAPPING(WRITE_PIN_TYPE)
      OP_CODE_MAPPING(READ_STORED_LINK_KEY)
      OP_CODE_MAPPING(WRITE_STORED_LINK_KEY)
      OP_CODE_MAPPING(DELETE_STORED_LINK_KEY)
      OP_CODE_MAPPING(WRITE_LOCAL_NAME)
      OP_CODE_MAPPING(READ_LOCAL_NAME)
      OP_CODE_MAPPING(READ_CONNECTION_ACCEPT_TIMEOUT)
      OP_CODE_MAPPING(WRITE_CONNECTION_ACCEPT_TIMEOUT)
      OP_CODE_MAPPING(READ_PAGE_TIMEOUT)
      OP_CODE_MAPPING(WRITE_PAGE_TIMEOUT)
      OP_CODE_MAPPING(READ_SCAN_ENABLE)
      OP_CODE_MAPPING(WRITE_SCAN_ENABLE)
      OP_CODE_MAPPING(READ_PAGE_SCAN_ACTIVITY)
      OP_CODE_MAPPING(WRITE_PAGE_SCAN_ACTIVITY)
      OP_CODE_MAPPING(READ_INQUIRY_SCAN_ACTIVITY)
      OP_CODE_MAPPING(WRITE_INQUIRY_SCAN_ACTIVITY)
      OP_CODE_MAPPING(READ_AUTHENTICATION_ENABLE)
      OP_CODE_MAPPING(WRITE_AUTHENTICATION_ENABLE)
      OP_CODE_MAPPING(READ_CLASS_OF_DEVICE)
      OP_CODE_MAPPING(WRITE_CLASS_OF_DEVICE)
      OP_CODE_MAPPING(READ_VOICE_SETTING)
      OP_CODE_MAPPING(WRITE_VOICE_SETTING)
      OP_CODE_MAPPING(READ_AUTOMATIC_FLUSH_TIMEOUT)
      OP_CODE_MAPPING(WRITE_AUTOMATIC_FLUSH_TIMEOUT)
      OP_CODE_MAPPING(READ_NUM_BROADCAST_RETRANSMITS)
      OP_CODE_MAPPING(WRITE_NUM_BROADCAST_RETRANSMITS)
      OP_CODE_MAPPING(READ_HOLD_MODE_ACTIVITY)
      OP_CODE_MAPPING(WRITE_HOLD_MODE_ACTIVITY)
      OP_CODE_MAPPING(READ_TRANSMIT_POWER_LEVEL)
      OP_CODE_MAPPING(READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE)
      OP_CODE_MAPPING(WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE)
      OP_CODE_MAPPING(SET_CONTROLLER_TO_HOST_FLOW_CONTROL)
      OP_CODE_MAPPING(HOST_BUFFER_SIZE)
      OP_CODE_MAPPING(HOST_NUM_COMPLETED_PACKETS)
      OP_CODE_MAPPING(READ_LINK_SUPERVISION_TIMEOUT)
      OP_CODE_MAPPING(WRITE_LINK_SUPERVISION_TIMEOUT)
      OP_CODE_MAPPING(READ_NUMBER_OF_SUPPORTED_IAC)
      OP_CODE_MAPPING(READ_CURRENT_IAC_LAP)
      OP_CODE_MAPPING(WRITE_CURRENT_IAC_LAP)
      OP_CODE_MAPPING(SET_AFH_HOST_CHANNEL_CLASSIFICATION)
      OP_CODE_MAPPING(READ_INQUIRY_SCAN_TYPE)
      OP_CODE_MAPPING(WRITE_INQUIRY_SCAN_TYPE)
      OP_CODE_MAPPING(READ_INQUIRY_MODE)
      OP_CODE_MAPPING(WRITE_INQUIRY_MODE)
      OP_CODE_MAPPING(READ_PAGE_SCAN_TYPE)
      OP_CODE_MAPPING(WRITE_PAGE_SCAN_TYPE)
      OP_CODE_MAPPING(READ_AFH_CHANNEL_ASSESSMENT_MODE)
      OP_CODE_MAPPING(WRITE_AFH_CHANNEL_ASSESSMENT_MODE)
      OP_CODE_MAPPING(READ_LOCAL_VERSION_INFORMATION)
      OP_CODE_MAPPING(READ_LOCAL_SUPPORTED_FEATURES)
      OP_CODE_MAPPING(READ_LOCAL_EXTENDED_FEATURES)
      OP_CODE_MAPPING(READ_BUFFER_SIZE)
      OP_CODE_MAPPING(READ_BD_ADDR)
      OP_CODE_MAPPING(READ_FAILED_CONTACT_COUNTER)
      OP_CODE_MAPPING(RESET_FAILED_CONTACT_COUNTER)
      OP_CODE_MAPPING(READ_LINK_QUALITY)
      OP_CODE_MAPPING(READ_RSSI)
      OP_CODE_MAPPING(READ_AFH_CHANNEL_MAP)
      OP_CODE_MAPPING(READ_CLOCK)
      OP_CODE_MAPPING(READ_LOOPBACK_MODE)
      OP_CODE_MAPPING(WRITE_LOOPBACK_MODE)
      OP_CODE_MAPPING(ENABLE_DEVICE_UNDER_TEST_MODE)
      OP_CODE_MAPPING(SETUP_SYNCHRONOUS_CONNECTION)
      OP_CODE_MAPPING(ACCEPT_SYNCHRONOUS_CONNECTION)
      OP_CODE_MAPPING(REJECT_SYNCHRONOUS_CONNECTION)
      OP_CODE_MAPPING(READ_EXTENDED_INQUIRY_RESPONSE)
      OP_CODE_MAPPING(WRITE_EXTENDED_INQUIRY_RESPONSE)
      OP_CODE_MAPPING(REFRESH_ENCRYPTION_KEY)
      OP_CODE_MAPPING(SNIFF_SUBRATING)
      OP_CODE_MAPPING(READ_SIMPLE_PAIRING_MODE)
      OP_CODE_MAPPING(WRITE_SIMPLE_PAIRING_MODE)
      OP_CODE_MAPPING(READ_LOCAL_OOB_DATA)
      OP_CODE_MAPPING(READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL)
      OP_CODE_MAPPING(WRITE_INQUIRY_TRANSMIT_POWER_LEVEL)
      OP_CODE_MAPPING(IO_CAPABILITY_REQUEST_REPLY)
      OP_CODE_MAPPING(USER_CONFIRMATION_REQUEST_REPLY)
      OP_CODE_MAPPING(USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(USER_PASSKEY_REQUEST_REPLY)
      OP_CODE_MAPPING(USER_PASSKEY_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(REMOTE_OOB_DATA_REQUEST_REPLY)
      OP_CODE_MAPPING(WRITE_SIMPLE_PAIRING_DEBUG_MODE)
      OP_CODE_MAPPING(REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(SEND_KEYPRESS_NOTIFICATION)
      OP_CODE_MAPPING(IO_CAPABILITY_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY)
      OP_CODE_MAPPING(READ_ENCRYPTION_KEY_SIZE)
      OP_CODE_MAPPING(READ_DATA_BLOCK_SIZE)
      OP_CODE_MAPPING(READ_LE_HOST_SUPPORT)
      OP_CODE_MAPPING(WRITE_LE_HOST_SUPPORT)
      OP_CODE_MAPPING(LE_SET_EVENT_MASK)
      OP_CODE_MAPPING(LE_READ_BUFFER_SIZE_V1)
      OP_CODE_MAPPING(LE_READ_LOCAL_SUPPORTED_FEATURES)
      OP_CODE_MAPPING(LE_SET_RANDOM_ADDRESS)
      OP_CODE_MAPPING(LE_SET_ADVERTISING_PARAMETERS)
      OP_CODE_MAPPING(LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER)
      OP_CODE_MAPPING(LE_SET_ADVERTISING_DATA)
      OP_CODE_MAPPING(LE_SET_SCAN_RESPONSE_DATA)
      OP_CODE_MAPPING(LE_SET_ADVERTISING_ENABLE)
      OP_CODE_MAPPING(LE_SET_SCAN_PARAMETERS)
      OP_CODE_MAPPING(LE_SET_SCAN_ENABLE)
      OP_CODE_MAPPING(LE_CREATE_CONNECTION)
      OP_CODE_MAPPING(LE_CREATE_CONNECTION_CANCEL)
      OP_CODE_MAPPING(LE_READ_CONNECT_LIST_SIZE)
      OP_CODE_MAPPING(LE_CLEAR_CONNECT_LIST)
      OP_CODE_MAPPING(LE_ADD_DEVICE_TO_CONNECT_LIST)
      OP_CODE_MAPPING(LE_REMOVE_DEVICE_FROM_CONNECT_LIST)
      OP_CODE_MAPPING(LE_CONNECTION_UPDATE)
      OP_CODE_MAPPING(LE_SET_HOST_CHANNEL_CLASSIFICATION)
      OP_CODE_MAPPING(LE_READ_CHANNEL_MAP)
      OP_CODE_MAPPING(LE_READ_REMOTE_FEATURES)
      OP_CODE_MAPPING(LE_ENCRYPT)
      OP_CODE_MAPPING(LE_RAND)
      OP_CODE_MAPPING(LE_START_ENCRYPTION)
      OP_CODE_MAPPING(LE_LONG_TERM_KEY_REQUEST_REPLY)
      OP_CODE_MAPPING(LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(LE_READ_SUPPORTED_STATES)
      OP_CODE_MAPPING(LE_RECEIVER_TEST)
      OP_CODE_MAPPING(LE_TRANSMITTER_TEST)
      OP_CODE_MAPPING(LE_TEST_END)
      OP_CODE_MAPPING(ENHANCED_SETUP_SYNCHRONOUS_CONNECTION)
      OP_CODE_MAPPING(ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION)
      OP_CODE_MAPPING(READ_LOCAL_SUPPORTED_CODECS_V1)
      OP_CODE_MAPPING(READ_SECURE_CONNECTIONS_HOST_SUPPORT)
      OP_CODE_MAPPING(WRITE_SECURE_CONNECTIONS_HOST_SUPPORT)
      OP_CODE_MAPPING(READ_LOCAL_OOB_EXTENDED_DATA)
      OP_CODE_MAPPING(WRITE_SECURE_CONNECTIONS_TEST_MODE)
      OP_CODE_MAPPING(LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY)
      OP_CODE_MAPPING(LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY)
      OP_CODE_MAPPING(LE_SET_DATA_LENGTH)
      OP_CODE_MAPPING(LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH)
      OP_CODE_MAPPING(LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH)
      OP_CODE_MAPPING(LE_READ_LOCAL_P_256_PUBLIC_KEY_COMMAND)
      OP_CODE_MAPPING(LE_GENERATE_DHKEY_COMMAND_V1)
      OP_CODE_MAPPING(LE_ADD_DEVICE_TO_RESOLVING_LIST)
      OP_CODE_MAPPING(LE_REMOVE_DEVICE_FROM_RESOLVING_LIST)
      OP_CODE_MAPPING(LE_CLEAR_RESOLVING_LIST)
      OP_CODE_MAPPING(LE_READ_RESOLVING_LIST_SIZE)
      OP_CODE_MAPPING(LE_READ_PEER_RESOLVABLE_ADDRESS)
      OP_CODE_MAPPING(LE_READ_LOCAL_RESOLVABLE_ADDRESS)
      OP_CODE_MAPPING(LE_SET_ADDRESS_RESOLUTION_ENABLE)
      OP_CODE_MAPPING(LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT)
      OP_CODE_MAPPING(LE_READ_MAXIMUM_DATA_LENGTH)
      OP_CODE_MAPPING(LE_READ_PHY)
      OP_CODE_MAPPING(LE_SET_DEFAULT_PHY)
      OP_CODE_MAPPING(LE_SET_PHY)
      OP_CODE_MAPPING(LE_ENHANCED_RECEIVER_TEST)
      OP_CODE_MAPPING(LE_ENHANCED_TRANSMITTER_TEST)
      OP_CODE_MAPPING(LE_SET_EXTENDED_ADVERTISING_RANDOM_ADDRESS)
      OP_CODE_MAPPING(LE_SET_EXTENDED_ADVERTISING_PARAMETERS)
      OP_CODE_MAPPING(LE_SET_EXTENDED_ADVERTISING_DATA)
      OP_CODE_MAPPING(LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE)
      OP_CODE_MAPPING(LE_SET_EXTENDED_ADVERTISING_ENABLE)
      OP_CODE_MAPPING(LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH)
      OP_CODE_MAPPING(LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS)
      OP_CODE_MAPPING(LE_REMOVE_ADVERTISING_SET)
      OP_CODE_MAPPING(LE_CLEAR_ADVERTISING_SETS)
      OP_CODE_MAPPING(LE_SET_PERIODIC_ADVERTISING_PARAM)
      OP_CODE_MAPPING(LE_SET_PERIODIC_ADVERTISING_DATA)
      OP_CODE_MAPPING(LE_SET_PERIODIC_ADVERTISING_ENABLE)
      OP_CODE_MAPPING(LE_SET_EXTENDED_SCAN_PARAMETERS)
      OP_CODE_MAPPING(LE_SET_EXTENDED_SCAN_ENABLE)
      OP_CODE_MAPPING(LE_EXTENDED_CREATE_CONNECTION)
      OP_CODE_MAPPING(LE_PERIODIC_ADVERTISING_CREATE_SYNC)
      OP_CODE_MAPPING(LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL)
      OP_CODE_MAPPING(LE_PERIODIC_ADVERTISING_TERMINATE_SYNC)
      OP_CODE_MAPPING(LE_ADD_DEVICE_TO_PERIODIC_ADVERTISING_LIST)
      OP_CODE_MAPPING(LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISING_LIST)
      OP_CODE_MAPPING(LE_CLEAR_PERIODIC_ADVERTISING_LIST)
      OP_CODE_MAPPING(LE_READ_PERIODIC_ADVERTISING_LIST_SIZE)
      OP_CODE_MAPPING(LE_READ_TRANSMIT_POWER)
      OP_CODE_MAPPING(LE_READ_RF_PATH_COMPENSATION_POWER)
      OP_CODE_MAPPING(LE_WRITE_RF_PATH_COMPENSATION_POWER)
      OP_CODE_MAPPING(LE_SET_PRIVACY_MODE)
      OP_CODE_MAPPING(LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE)
      OP_CODE_MAPPING(LE_PERIODIC_ADVERTISING_SYNC_TRANSFER)
      OP_CODE_MAPPING(LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER)
      OP_CODE_MAPPING(LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS)
      OP_CODE_MAPPING(LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS)
      OP_CODE_MAPPING(LE_GENERATE_DHKEY_COMMAND)
      OP_CODE_MAPPING(LE_MODIFY_SLEEP_CLOCK_ACCURACY)
      OP_CODE_MAPPING(LE_READ_BUFFER_SIZE_V2)
      OP_CODE_MAPPING(LE_READ_ISO_TX_SYNC)
      OP_CODE_MAPPING(LE_SET_CIG_PARAMETERS)
      OP_CODE_MAPPING(LE_CREATE_CIS)
      OP_CODE_MAPPING(LE_REMOVE_CIG)
      OP_CODE_MAPPING(LE_ACCEPT_CIS_REQUEST)
      OP_CODE_MAPPING(LE_REJECT_CIS_REQUEST)
      OP_CODE_MAPPING(LE_CREATE_BIG)
      OP_CODE_MAPPING(LE_TERMINATE_BIG)
      OP_CODE_MAPPING(LE_BIG_CREATE_SYNC)
      OP_CODE_MAPPING(LE_BIG_TERMINATE_SYNC)
      OP_CODE_MAPPING(LE_REQUEST_PEER_SCA)
      OP_CODE_MAPPING(LE_SETUP_ISO_DATA_PATH)
      OP_CODE_MAPPING(LE_REMOVE_ISO_DATA_PATH)
      OP_CODE_MAPPING(LE_SET_HOST_FEATURE)
      OP_CODE_MAPPING(LE_READ_ISO_LINK_QUALITY)
      OP_CODE_MAPPING(LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL)
      OP_CODE_MAPPING(LE_READ_REMOTE_TRANSMIT_POWER_LEVEL)
      OP_CODE_MAPPING(LE_SET_PATH_LOSS_REPORTING_PARAMETERS)
      OP_CODE_MAPPING(LE_SET_PATH_LOSS_REPORTING_ENABLE)
      OP_CODE_MAPPING(LE_SET_TRANSMIT_POWER_REPORTING_ENABLE)
      OP_CODE_MAPPING(SET_ECOSYSTEM_BASE_INTERVAL)
      OP_CODE_MAPPING(READ_LOCAL_SUPPORTED_CODECS_V2)
      OP_CODE_MAPPING(READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES)
      OP_CODE_MAPPING(READ_LOCAL_SUPPORTED_CONTROLLER_DELAY)
      OP_CODE_MAPPING(CONFIGURE_DATA_PATH)
      OP_CODE_MAPPING(ENHANCED_FLUSH)

      // vendor specific
      case OpCode::LE_GET_VENDOR_CAPABILITIES:
        return vendor_capabilities_.is_supported_ == 0x01;
      case OpCode::LE_MULTI_ADVT:
        return vendor_capabilities_.max_advt_instances_ != 0x00;
      case OpCode::LE_BATCH_SCAN:
        return vendor_capabilities_.total_scan_results_storage_ != 0x00;
      case OpCode::LE_ADV_FILTER:
        return vendor_capabilities_.filtering_support_ == 0x01;
      case OpCode::LE_ENERGY_INFO:
        return vendor_capabilities_.activity_energy_info_support_ == 0x01;
      case OpCode::LE_EXTENDED_SCAN_PARAMS:
        return vendor_capabilities_.extended_scan_support_ == 0x01;
      case OpCode::CONTROLLER_DEBUG_INFO:
        return vendor_capabilities_.debug_logging_supported_ == 0x01;
      case OpCode::CONTROLLER_A2DP_OPCODE:
        return vendor_capabilities_.a2dp_source_offload_capability_mask_ != 0x00;
      case OpCode::CONTROLLER_BQR:
        return vendor_capabilities_.bluetooth_quality_report_support_ == 0x01;
      // undefined in local_supported_commands_
      case OpCode::READ_LOCAL_SUPPORTED_COMMANDS:
        return true;
      case OpCode::NONE:
        return false;
    }
    return false;
  }
#undef OP_CODE_MAPPING

  Controller& module_;

  HciLayer* hci_;

  CompletedAclPacketsCallback acl_credits_callback_{};
  CompletedAclPacketsCallback acl_monitor_credits_callback_{};
  LocalVersionInformation local_version_information_;
  std::array<uint8_t, 64> local_supported_commands_;
  uint8_t maximum_page_number_;
  std::vector<uint64_t> extended_lmp_features_array_;
  uint16_t acl_buffer_length_ = 0;
  uint16_t acl_buffers_ = 0;
  uint8_t sco_buffer_length_ = 0;
  uint16_t sco_buffers_ = 0;
  Address mac_address_;
  std::string local_name_;
  LeBufferSize le_buffer_size_;
  LeBufferSize iso_buffer_size_;
  uint64_t le_local_supported_features_;
  uint64_t le_supported_states_;
  uint8_t le_connect_list_size_;
  uint8_t le_resolving_list_size_;
  LeMaximumDataLength le_maximum_data_length_;
  uint16_t le_maximum_advertising_data_length_;
  uint16_t le_suggested_default_data_length_;
  uint8_t le_number_supported_advertising_sets_;
  uint8_t le_periodic_advertiser_list_size_;
  VendorCapabilities vendor_capabilities_;
};  // namespace hci

Controller::Controller() : impl_(std::make_unique<impl>(*this)) {}

Controller::~Controller() = default;

void Controller::RegisterCompletedAclPacketsCallback(CompletedAclPacketsCallback cb) {
  CallOn(impl_.get(), &impl::register_completed_acl_packets_callback, cb);
}

void Controller::UnregisterCompletedAclPacketsCallback() {
  CallOn(impl_.get(), &impl::unregister_completed_acl_packets_callback);
}

void Controller::RegisterCompletedMonitorAclPacketsCallback(CompletedAclPacketsCallback cb) {
  CallOn(impl_.get(), &impl::register_completed_monitor_acl_packets_callback, cb);
}

void Controller::UnregisterCompletedMonitorAclPacketsCallback() {
  CallOn(impl_.get(), &impl::unregister_completed_monitor_acl_packets_callback);
}

std::string Controller::GetLocalName() const {
  return impl_->local_name_;
}

LocalVersionInformation Controller::GetLocalVersionInformation() const {
  return impl_->local_version_information_;
}

#define BIT(x) (0x1ULL << (x))

#define LOCAL_FEATURE_ACCESSOR(name, page, bit) \
  bool Controller::name() const {               \
    return GetLocalFeatures(page) & BIT(bit);   \
  }

LOCAL_FEATURE_ACCESSOR(SupportsSimplePairing, 0, 51)
LOCAL_FEATURE_ACCESSOR(SupportsSecureConnections, 2, 8)
LOCAL_FEATURE_ACCESSOR(SupportsSimultaneousLeBrEdr, 0, 49)
LOCAL_FEATURE_ACCESSOR(SupportsInterlacedInquiryScan, 0, 28)
LOCAL_FEATURE_ACCESSOR(SupportsRssiWithInquiryResults, 0, 30)
LOCAL_FEATURE_ACCESSOR(SupportsExtendedInquiryResponse, 0, 48)
LOCAL_FEATURE_ACCESSOR(SupportsRoleSwitch, 0, 5)
LOCAL_FEATURE_ACCESSOR(Supports3SlotPackets, 0, 0)
LOCAL_FEATURE_ACCESSOR(Supports5SlotPackets, 0, 1)
LOCAL_FEATURE_ACCESSOR(SupportsClassic2mPhy, 0, 25)
LOCAL_FEATURE_ACCESSOR(SupportsClassic3mPhy, 0, 26)
LOCAL_FEATURE_ACCESSOR(Supports3SlotEdrPackets, 0, 39)
LOCAL_FEATURE_ACCESSOR(Supports5SlotEdrPackets, 0, 40)
LOCAL_FEATURE_ACCESSOR(SupportsSco, 0, 11)
LOCAL_FEATURE_ACCESSOR(SupportsHv2Packets, 0, 12)
LOCAL_FEATURE_ACCESSOR(SupportsHv3Packets, 0, 13)
LOCAL_FEATURE_ACCESSOR(SupportsEv3Packets, 0, 31)
LOCAL_FEATURE_ACCESSOR(SupportsEv4Packets, 0, 32)
LOCAL_FEATURE_ACCESSOR(SupportsEv5Packets, 0, 33)
LOCAL_FEATURE_ACCESSOR(SupportsEsco2mPhy, 0, 45)
LOCAL_FEATURE_ACCESSOR(SupportsEsco3mPhy, 0, 46)
LOCAL_FEATURE_ACCESSOR(Supports3SlotEscoEdrPackets, 0, 47)
LOCAL_FEATURE_ACCESSOR(SupportsHoldMode, 0, 6)
LOCAL_FEATURE_ACCESSOR(SupportsSniffMode, 0, 7)
LOCAL_FEATURE_ACCESSOR(SupportsParkMode, 0, 8)
LOCAL_FEATURE_ACCESSOR(SupportsNonFlushablePb, 0, 54)
LOCAL_FEATURE_ACCESSOR(SupportsSniffSubrating, 0, 41)
LOCAL_FEATURE_ACCESSOR(SupportsEncryptionPause, 0, 42)
LOCAL_FEATURE_ACCESSOR(SupportsBle, 0, 38)

#define LOCAL_LE_FEATURE_ACCESSOR(name, bit) \
  bool Controller::name() const {            \
    return GetLocalLeFeatures() & BIT(bit);  \
  }

LOCAL_LE_FEATURE_ACCESSOR(SupportsBleConnectionParameterRequest, 1)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBleConnectionParametersRequest, 2)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBlePeripheralInitiatedFeatureExchange, 3)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBlePacketExtension, 5)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBlePrivacy, 6)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBle2mPhy, 8)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBleCodedPhy, 11)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBleExtendedAdvertising, 12)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBlePeriodicAdvertising, 13)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBlePeriodicAdvertisingSyncTransferSender, 24)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBlePeriodicAdvertisingSyncTransferRecipient, 25)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBleConnectedIsochronousStreamCentral, 28)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBleConnectedIsochronousStreamPeripheral, 29)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBleIsochronousBroadcaster, 30)
LOCAL_LE_FEATURE_ACCESSOR(SupportsBleSynchronizedReceiver, 31)

uint64_t Controller::GetLocalFeatures(uint8_t page_number) const {
  if (page_number <= impl_->maximum_page_number_) {
    return impl_->extended_lmp_features_array_[page_number];
  }
  return 0x00;
}

uint16_t Controller::GetAclPacketLength() const {
  return impl_->acl_buffer_length_;
}

uint16_t Controller::GetNumAclPacketBuffers() const {
  return impl_->acl_buffers_;
}

uint8_t Controller::GetScoPacketLength() const {
  return impl_->sco_buffer_length_;
}

uint16_t Controller::GetNumScoPacketBuffers() const {
  return impl_->sco_buffers_;
}

Address Controller::GetMacAddress() const {
  return impl_->mac_address_;
}

void Controller::SetEventMask(uint64_t event_mask) {
  CallOn(impl_.get(), &impl::set_event_mask, event_mask);
}

void Controller::Reset() {
  CallOn(impl_.get(), &impl::reset);
}

void Controller::SetEventFilterClearAll() {
  std::unique_ptr<SetEventFilterClearAllBuilder> packet = SetEventFilterClearAllBuilder::Create();
  CallOn(impl_.get(), &impl::set_event_filter, std::move(packet));
}

void Controller::SetEventFilterInquiryResultAllDevices() {
  std::unique_ptr<SetEventFilterInquiryResultAllDevicesBuilder> packet =
      SetEventFilterInquiryResultAllDevicesBuilder::Create();
  CallOn(impl_.get(), &impl::set_event_filter, std::move(packet));
}

void Controller::SetEventFilterInquiryResultClassOfDevice(ClassOfDevice class_of_device,
                                                          ClassOfDevice class_of_device_mask) {
  std::unique_ptr<SetEventFilterInquiryResultClassOfDeviceBuilder> packet =
      SetEventFilterInquiryResultClassOfDeviceBuilder::Create(class_of_device, class_of_device_mask);
  CallOn(impl_.get(), &impl::set_event_filter, std::move(packet));
}

void Controller::SetEventFilterInquiryResultAddress(Address address) {
  std::unique_ptr<SetEventFilterInquiryResultAddressBuilder> packet =
      SetEventFilterInquiryResultAddressBuilder::Create(address);
  CallOn(impl_.get(), &impl::set_event_filter, std::move(packet));
}

void Controller::SetEventFilterConnectionSetupAllDevices(AutoAcceptFlag auto_accept_flag) {
  std::unique_ptr<SetEventFilterConnectionSetupAllDevicesBuilder> packet =
      SetEventFilterConnectionSetupAllDevicesBuilder::Create(auto_accept_flag);
  CallOn(impl_.get(), &impl::set_event_filter, std::move(packet));
}

void Controller::SetEventFilterConnectionSetupClassOfDevice(ClassOfDevice class_of_device,
                                                            ClassOfDevice class_of_device_mask,
                                                            AutoAcceptFlag auto_accept_flag) {
  std::unique_ptr<SetEventFilterConnectionSetupClassOfDeviceBuilder> packet =
      SetEventFilterConnectionSetupClassOfDeviceBuilder::Create(class_of_device, class_of_device_mask,
                                                                auto_accept_flag);
  CallOn(impl_.get(), &impl::set_event_filter, std::move(packet));
}

void Controller::SetEventFilterConnectionSetupAddress(Address address, AutoAcceptFlag auto_accept_flag) {
  std::unique_ptr<SetEventFilterConnectionSetupAddressBuilder> packet =
      SetEventFilterConnectionSetupAddressBuilder::Create(address, auto_accept_flag);
  CallOn(impl_.get(), &impl::set_event_filter, std::move(packet));
}

void Controller::WriteLocalName(std::string local_name) {
  impl_->local_name_ = local_name;
  CallOn(impl_.get(), &impl::write_local_name, local_name);
}

void Controller::HostBufferSize(uint16_t host_acl_data_packet_length, uint8_t host_synchronous_data_packet_length,
                                uint16_t host_total_num_acl_data_packets,
                                uint16_t host_total_num_synchronous_data_packets) {
  CallOn(
      impl_.get(),
      &impl::host_buffer_size,
      host_acl_data_packet_length,
      host_synchronous_data_packet_length,
      host_total_num_acl_data_packets,
      host_total_num_synchronous_data_packets);
}

void Controller::LeSetEventMask(uint64_t le_event_mask) {
  CallOn(impl_.get(), &impl::le_set_event_mask, le_event_mask);
}

LeBufferSize Controller::GetLeBufferSize() const {
  return impl_->le_buffer_size_;
}

uint64_t Controller::GetLocalLeFeatures() const {
  return impl_->le_local_supported_features_;
}

LeBufferSize Controller::GetControllerIsoBufferSize() const {
  return impl_->iso_buffer_size_;
}

uint64_t Controller::GetControllerLeLocalSupportedFeatures() const {
  return impl_->le_local_supported_features_;
}

uint64_t Controller::GetLeSupportedStates() const {
  return impl_->le_supported_states_;
}

uint8_t Controller::GetLeConnectListSize() const {
  return impl_->le_connect_list_size_;
}

uint8_t Controller::GetLeResolvingListSize() const {
  return impl_->le_resolving_list_size_;
}

LeMaximumDataLength Controller::GetLeMaximumDataLength() const {
  return impl_->le_maximum_data_length_;
}

uint16_t Controller::GetLeMaximumAdvertisingDataLength() const {
  return impl_->le_maximum_advertising_data_length_;
}

uint16_t Controller::GetLeSuggestedDefaultDataLength() const {
  return impl_->le_suggested_default_data_length_;
}

uint8_t Controller::GetLeNumberOfSupportedAdverisingSets() const {
  return impl_->le_number_supported_advertising_sets_;
}

VendorCapabilities Controller::GetVendorCapabilities() const {
  return impl_->vendor_capabilities_;
}

uint8_t Controller::GetLePeriodicAdvertiserListSize() const {
  return impl_->le_periodic_advertiser_list_size_;
}

bool Controller::IsSupported(bluetooth::hci::OpCode op_code) const {
  return impl_->is_supported(op_code);
}

const ModuleFactory Controller::Factory = ModuleFactory([]() { return new Controller(); });

void Controller::ListDependencies(ModuleList* list) {
  list->add<hci::HciLayer>();
}

void Controller::Start() {
  impl_->Start(GetDependency<hci::HciLayer>());
}

void Controller::Stop() {
  impl_->Stop();
}

std::string Controller::ToString() const {
  return "Controller";
}
}  // namespace hci
}  // namespace bluetooth
