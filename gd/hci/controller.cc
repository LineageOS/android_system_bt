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
#include <utility>

#include "common/bind.h"
#include "common/callback.h"
#include "hci/hci_layer.h"

namespace bluetooth {
namespace hci {

using common::Bind;
using common::BindOnce;
using common::Callback;
using common::Closure;
using common::OnceCallback;
using common::OnceClosure;
using os::Handler;

struct Controller::impl {
  impl(Controller& module) : module_(module) {}

  void Start(hci::HciLayer* hci) {
    hci_ = hci;
    hci_->RegisterEventHandler(EventCode::NUMBER_OF_COMPLETED_PACKETS,
                               Bind(&Controller::impl::NumberOfCompletedPackets, common::Unretained(this)),
                               module_.GetHandler());

    hci_->EnqueueCommand(ReadLocalNameBuilder::Create(),
                         BindOnce(&Controller::impl::read_local_name_complete_handler, common::Unretained(this)),
                         module_.GetHandler());
    hci_->EnqueueCommand(
        ReadLocalVersionInformationBuilder::Create(),
        BindOnce(&Controller::impl::read_local_version_information_complete_handler, common::Unretained(this)),
        module_.GetHandler());
    hci_->EnqueueCommand(
        ReadLocalSupportedCommandsBuilder::Create(),
        BindOnce(&Controller::impl::read_local_supported_commands_complete_handler, common::Unretained(this)),
        module_.GetHandler());
    hci_->EnqueueCommand(
        ReadLocalSupportedFeaturesBuilder::Create(),
        BindOnce(&Controller::impl::read_local_supported_features_complete_handler, common::Unretained(this)),
        module_.GetHandler());

    // Wait for all extended features read
    std::promise<void> features_promise;
    auto features_future = features_promise.get_future();
    hci_->EnqueueCommand(ReadLocalExtendedFeaturesBuilder::Create(0x00),
                         BindOnce(&Controller::impl::read_local_extended_features_complete_handler,
                                  common::Unretained(this), std::move(features_promise)),
                         module_.GetHandler());
    features_future.wait();

    hci_->EnqueueCommand(ReadBufferSizeBuilder::Create(),
                         BindOnce(&Controller::impl::read_buffer_size_complete_handler, common::Unretained(this)),
                         module_.GetHandler());

    hci_->EnqueueCommand(LeReadBufferSizeBuilder::Create(),
                         BindOnce(&Controller::impl::le_read_buffer_size_handler, common::Unretained(this)),
                         module_.GetHandler());

    hci_->EnqueueCommand(
        LeReadLocalSupportedFeaturesBuilder::Create(),
        BindOnce(&Controller::impl::le_read_local_supported_features_handler, common::Unretained(this)),
        module_.GetHandler());

    hci_->EnqueueCommand(LeReadSupportedStatesBuilder::Create(),
                         BindOnce(&Controller::impl::le_read_supported_states_handler, common::Unretained(this)),
                         module_.GetHandler());

    if (is_support(OpCode::LE_READ_MAXIMUM_DATA_LENGTH)) {
      hci_->EnqueueCommand(LeReadMaximumDataLengthBuilder::Create(),
                           BindOnce(&Controller::impl::le_read_maximum_data_length_handler, common::Unretained(this)),
                           module_.GetHandler());
    }
    if (is_support(OpCode::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH)) {
      hci_->EnqueueCommand(
          LeReadMaximumAdvertisingDataLengthBuilder::Create(),
          BindOnce(&Controller::impl::le_read_maximum_advertising_data_length_handler, common::Unretained(this)),
          module_.GetHandler());
    }
    if (is_support(OpCode::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS)) {
      hci_->EnqueueCommand(
          LeReadNumberOfSupportedAdvertisingSetsBuilder::Create(),
          BindOnce(&Controller::impl::le_read_number_of_supported_advertising_sets_handler, common::Unretained(this)),
          module_.GetHandler());
    }

    // We only need to synchronize the last read. Make BD_ADDR to be the last one.
    std::promise<void> promise;
    auto future = promise.get_future();
    hci_->EnqueueCommand(
        ReadBdAddrBuilder::Create(),
        BindOnce(&Controller::impl::read_controller_mac_address_handler, common::Unretained(this), std::move(promise)),
        module_.GetHandler());
    future.wait();
  }

  void Stop() {
    hci_->UnregisterEventHandler(EventCode::NUMBER_OF_COMPLETED_PACKETS);
    hci_ = nullptr;
  }

  void NumberOfCompletedPackets(EventPacketView event) {
    ASSERT(acl_credits_handler_ != nullptr);
    auto complete_view = NumberOfCompletedPacketsView::Create(event);
    ASSERT(complete_view.IsValid());
    for (auto completed_packets : complete_view.GetCompletedPackets()) {
      uint16_t handle = completed_packets.connection_handle_;
      uint16_t credits = completed_packets.host_num_of_completed_packets_;
      acl_credits_handler_->Post(Bind(acl_credits_callback_, handle, credits));
    }
  }

  void RegisterCompletedAclPacketsCallback(Callback<void(uint16_t /* handle */, uint16_t /* packets */)> cb,
                                           Handler* handler) {
    ASSERT(acl_credits_handler_ == nullptr);
    acl_credits_callback_ = cb;
    acl_credits_handler_ = handler;
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

  void read_local_supported_features_complete_handler(CommandCompleteView view) {
    auto complete_view = ReadLocalSupportedFeaturesCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    local_supported_features_ = complete_view.GetLmpFeatures();
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
      hci_->EnqueueCommand(ReadLocalExtendedFeaturesBuilder::Create(page_number),
                           BindOnce(&Controller::impl::read_local_extended_features_complete_handler,
                                    common::Unretained(this), std::move(promise)),
                           module_.GetHandler());
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
    auto complete_view = LeReadBufferSizeCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_buffer_size_ = complete_view.GetLeBufferSize();
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

  void le_read_maximum_data_length_handler(CommandCompleteView view) {
    auto complete_view = LeReadMaximumDataLengthCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    ErrorCode status = complete_view.GetStatus();
    ASSERT_LOG(status == ErrorCode::SUCCESS, "Status 0x%02hhx, %s", status, ErrorCodeText(status).c_str());
    le_maximum_data_length_ = complete_view.GetLeMaximumDataLength();
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

  void set_event_mask(uint64_t event_mask) {
    std::unique_ptr<SetEventMaskBuilder> packet = SetEventMaskBuilder::Create(event_mask);
    hci_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandCompleteView complete) { /* TODO */ }),
                         module_.GetHandler());
  }

  void reset() {
    std::unique_ptr<ResetBuilder> packet = ResetBuilder::Create();
    hci_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandCompleteView complete) { /* TODO */ }),
                         module_.GetHandler());
  }

  void set_event_filter(std::unique_ptr<SetEventFilterBuilder> packet) {
    hci_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandCompleteView complete) { /* TODO */ }),
                         module_.GetHandler());
  }

  void write_local_name(std::string local_name) {
    ASSERT(local_name.length() <= 248);
    // Fill remaining char with 0
    local_name.append(std::string(248 - local_name.length(), '\0'));
    std::array<uint8_t, 248> local_name_array;
    std::copy(std::begin(local_name), std::end(local_name), std::begin(local_name_array));

    std::unique_ptr<WriteLocalNameBuilder> packet = WriteLocalNameBuilder::Create(local_name_array);
    hci_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandCompleteView complete) { /* TODO */ }),
                         module_.GetHandler());
  }

  void host_buffer_size(uint16_t host_acl_data_packet_length, uint8_t host_synchronous_data_packet_length,
                        uint16_t host_total_num_acl_data_packets, uint16_t host_total_num_synchronous_data_packets) {
    std::unique_ptr<HostBufferSizeBuilder> packet =
        HostBufferSizeBuilder::Create(host_acl_data_packet_length, host_synchronous_data_packet_length,
                                      host_total_num_acl_data_packets, host_total_num_synchronous_data_packets);
    hci_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandCompleteView complete) { /* TODO */ }),
                         module_.GetHandler());
  }

  void le_set_event_mask(uint64_t le_event_mask) {
    std::unique_ptr<LeSetEventMaskBuilder> packet = LeSetEventMaskBuilder::Create(le_event_mask);
    hci_->EnqueueCommand(std::move(packet), common::BindOnce([](CommandCompleteView complete) { /* TODO */ }),
                         module_.GetHandler());
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

  bool is_support(OpCode op_code) {
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
      OP_CODE_MAPPING(MASTER_LINK_KEY)
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
      OP_CODE_MAPPING(READ_ENCRYPTION_KEY_SIZE)
      OP_CODE_MAPPING(READ_DATA_BLOCK_SIZE)
      OP_CODE_MAPPING(READ_LE_HOST_SUPPORT)
      OP_CODE_MAPPING(WRITE_LE_HOST_SUPPORT)
      OP_CODE_MAPPING(LE_SET_EVENT_MASK)
      OP_CODE_MAPPING(LE_READ_BUFFER_SIZE)
      OP_CODE_MAPPING(LE_READ_LOCAL_SUPPORTED_FEATURES)
      OP_CODE_MAPPING(LE_SET_RANDOM_ADDRESS)
      OP_CODE_MAPPING(LE_SET_ADVERTISING_PARAMETERS)
      OP_CODE_MAPPING(LE_READ_ADVERTISING_CHANNEL_TX_POWER)
      OP_CODE_MAPPING(LE_SET_ADVERTISING_DATA)
      OP_CODE_MAPPING(LE_SET_SCAN_RESPONSE_DATA)
      OP_CODE_MAPPING(LE_SET_ADVERTISING_ENABLE)
      OP_CODE_MAPPING(LE_SET_SCAN_PARAMETERS)
      OP_CODE_MAPPING(LE_SET_SCAN_ENABLE)
      OP_CODE_MAPPING(LE_CREATE_CONNECTION)
      OP_CODE_MAPPING(LE_CREATE_CONNECTION_CANCEL)
      OP_CODE_MAPPING(LE_READ_WHITE_LIST_SIZE)
      OP_CODE_MAPPING(LE_CLEAR_WHITE_LIST)
      OP_CODE_MAPPING(LE_ADD_DEVICE_TO_WHITE_LIST)
      OP_CODE_MAPPING(LE_REMOVE_DEVICE_FROM_WHITE_LIST)
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
      OP_CODE_MAPPING(READ_LOCAL_SUPPORTED_CODECS)
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
      OP_CODE_MAPPING(LE_GENERATE_DHKEY_COMMAND)
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
      // vendor specific
      case OpCode::LE_GET_VENDOR_CAPABILITIES:
      case OpCode::LE_MULTI_ADVT:
      case OpCode::LE_BATCH_SCAN:
      case OpCode::LE_ADV_FILTER:
      case OpCode::LE_TRACK_ADV:
      case OpCode::LE_ENERGY_INFO:
      case OpCode::LE_EXTENDED_SCAN_PARAMS:
      case OpCode::CONTROLLER_DEBUG_INFO:
      case OpCode::CONTROLLER_A2DP_OPCODE:
        return true;
      // undefined in local_supported_commands_
      case OpCode::CREATE_NEW_UNIT_KEY:
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

  Callback<void(uint16_t, uint16_t)> acl_credits_callback_;
  Handler* acl_credits_handler_ = nullptr;
  LocalVersionInformation local_version_information_;
  std::array<uint8_t, 64> local_supported_commands_;
  uint64_t local_supported_features_;
  uint8_t maximum_page_number_;
  std::vector<uint64_t> extended_lmp_features_array_;
  uint16_t acl_buffer_length_ = 0;
  uint16_t acl_buffers_ = 0;
  uint8_t sco_buffer_length_ = 0;
  uint16_t sco_buffers_ = 0;
  Address mac_address_;
  std::string local_name_;
  LeBufferSize le_buffer_size_;
  uint64_t le_local_supported_features_;
  uint64_t le_supported_states_;
  LeMaximumDataLength le_maximum_data_length_;
  uint16_t le_maximum_advertising_data_length_;
  uint16_t le_number_supported_advertising_sets_;
};  // namespace hci

Controller::Controller() : impl_(std::make_unique<impl>(*this)) {}

Controller::~Controller() = default;

void Controller::RegisterCompletedAclPacketsCallback(Callback<void(uint16_t /* handle */, uint16_t /* packets */)> cb,
                                                     Handler* handler) {
  impl_->RegisterCompletedAclPacketsCallback(cb, handler);  // TODO hsz: why here?
}

std::string Controller::GetControllerLocalName() {
  return impl_->local_name_;
}

LocalVersionInformation Controller::GetControllerLocalVersionInformation() {
  return impl_->local_version_information_;
}

std::array<uint8_t, 64> Controller::GetControllerLocalSupportedCommands() {
  return impl_->local_supported_commands_;
}

uint8_t Controller::GetControllerLocalExtendedFeaturesMaxPageNumber() {
  return impl_->maximum_page_number_;
}

uint64_t Controller::GetControllerLocalSupportedFeatures() {
  return impl_->local_supported_features_;
}

uint64_t Controller::GetControllerLocalExtendedFeatures(uint8_t page_number) {
  if (page_number <= impl_->maximum_page_number_) {
    return impl_->extended_lmp_features_array_[page_number];
  }
  return 0x00;
}

uint16_t Controller::GetControllerAclPacketLength() {
  return impl_->acl_buffer_length_;
}

uint16_t Controller::GetControllerNumAclPacketBuffers() {
  return impl_->acl_buffers_;
}

uint8_t Controller::GetControllerScoPacketLength() {
  return impl_->sco_buffer_length_;
}

uint16_t Controller::GetControllerNumScoPacketBuffers() {
  return impl_->sco_buffers_;
}

Address Controller::GetControllerMacAddress() {
  return impl_->mac_address_;
}

void Controller::SetEventMask(uint64_t event_mask) {
  GetHandler()->Post(common::BindOnce(&impl::set_event_mask, common::Unretained(impl_.get()), event_mask));
}

void Controller::Reset() {
  GetHandler()->Post(common::BindOnce(&impl::reset, common::Unretained(impl_.get())));
}

void Controller::SetEventFilterClearAll() {
  std::unique_ptr<SetEventFilterClearAllBuilder> packet = SetEventFilterClearAllBuilder::Create();
  GetHandler()->Post(common::BindOnce(&impl::set_event_filter, common::Unretained(impl_.get()), std::move(packet)));
}

void Controller::SetEventFilterInquiryResultAllDevices() {
  std::unique_ptr<SetEventFilterInquiryResultAllDevicesBuilder> packet =
      SetEventFilterInquiryResultAllDevicesBuilder::Create();
  GetHandler()->Post(common::BindOnce(&impl::set_event_filter, common::Unretained(impl_.get()), std::move(packet)));
}

void Controller::SetEventFilterInquiryResultClassOfDevice(ClassOfDevice class_of_device,
                                                          ClassOfDevice class_of_device_mask) {
  std::unique_ptr<SetEventFilterInquiryResultClassOfDeviceBuilder> packet =
      SetEventFilterInquiryResultClassOfDeviceBuilder::Create(class_of_device, class_of_device_mask);
  GetHandler()->Post(common::BindOnce(&impl::set_event_filter, common::Unretained(impl_.get()), std::move(packet)));
}

void Controller::SetEventFilterInquiryResultAddress(Address address) {
  std::unique_ptr<SetEventFilterInquiryResultAddressBuilder> packet =
      SetEventFilterInquiryResultAddressBuilder::Create(address);
  GetHandler()->Post(common::BindOnce(&impl::set_event_filter, common::Unretained(impl_.get()), std::move(packet)));
}

void Controller::SetEventFilterConnectionSetupAllDevices(AutoAcceptFlag auto_accept_flag) {
  std::unique_ptr<SetEventFilterConnectionSetupAllDevicesBuilder> packet =
      SetEventFilterConnectionSetupAllDevicesBuilder::Create(auto_accept_flag);
  GetHandler()->Post(common::BindOnce(&impl::set_event_filter, common::Unretained(impl_.get()), std::move(packet)));
}

void Controller::SetEventFilterConnectionSetupClassOfDevice(ClassOfDevice class_of_device,
                                                            ClassOfDevice class_of_device_mask,
                                                            AutoAcceptFlag auto_accept_flag) {
  std::unique_ptr<SetEventFilterConnectionSetupClassOfDeviceBuilder> packet =
      SetEventFilterConnectionSetupClassOfDeviceBuilder::Create(class_of_device, class_of_device_mask,
                                                                auto_accept_flag);
  GetHandler()->Post(common::BindOnce(&impl::set_event_filter, common::Unretained(impl_.get()), std::move(packet)));
}

void Controller::SetEventFilterConnectionSetupAddress(Address address, AutoAcceptFlag auto_accept_flag) {
  std::unique_ptr<SetEventFilterConnectionSetupAddressBuilder> packet =
      SetEventFilterConnectionSetupAddressBuilder::Create(address, auto_accept_flag);
  GetHandler()->Post(common::BindOnce(&impl::set_event_filter, common::Unretained(impl_.get()), std::move(packet)));
}

void Controller::WriteLocalName(std::string local_name) {
  impl_->local_name_ = local_name;
  GetHandler()->Post(common::BindOnce(&impl::write_local_name, common::Unretained(impl_.get()), local_name));
}

void Controller::HostBufferSize(uint16_t host_acl_data_packet_length, uint8_t host_synchronous_data_packet_length,
                                uint16_t host_total_num_acl_data_packets,
                                uint16_t host_total_num_synchronous_data_packets) {
  GetHandler()->Post(common::BindOnce(&impl::host_buffer_size, common::Unretained(impl_.get()),
                                      host_acl_data_packet_length, host_synchronous_data_packet_length,
                                      host_total_num_acl_data_packets, host_total_num_synchronous_data_packets));
}

void Controller::LeSetEventMask(uint64_t le_event_mask) {
  GetHandler()->Post(common::BindOnce(&impl::le_set_event_mask, common::Unretained(impl_.get()), le_event_mask));
}

LeBufferSize Controller::GetControllerLeBufferSize() {
  return impl_->le_buffer_size_;
}

uint64_t Controller::GetControllerLeLocalSupportedFeatures() {
  return impl_->le_local_supported_features_;
}

uint64_t Controller::GetControllerLeSupportedStates() {
  return impl_->le_supported_states_;
}

LeMaximumDataLength Controller::GetControllerLeMaximumDataLength() {
  return impl_->le_maximum_data_length_;
}

uint16_t Controller::GetControllerLeMaximumAdvertisingDataLength() {
  return impl_->le_maximum_advertising_data_length_;
}

uint16_t Controller::GetControllerLeNumberOfSupportedAdverisingSets() {
  return impl_->le_number_supported_advertising_sets_;
}

bool Controller::IsSupport(bluetooth::hci::OpCode op_code) {
  return impl_->is_support(op_code);
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
}  // namespace hci
}  // namespace bluetooth
