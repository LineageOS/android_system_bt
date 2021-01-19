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
#include <memory>
#include <mutex>

#include "hci/acl_manager.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "hci/le_advertising_interface.h"
#include "hci/le_advertising_manager.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace hci {

const ModuleFactory LeAdvertisingManager::Factory = ModuleFactory([]() { return new LeAdvertisingManager(); });

enum class AdvertisingApiType {
  LEGACY = 1,
  ANDROID_HCI = 2,
  EXTENDED = 3,
};

enum class AdvertisingFlag : uint8_t {
  LE_LIMITED_DISCOVERABLE = 0x01,
  LE_GENERAL_DISCOVERABLE = 0x02,
  BR_EDR_NOT_SUPPORTED = 0x04,
  SIMULTANEOUS_LE_AND_BR_EDR_CONTROLLER = 0x08,
  SIMULTANEOUS_LE_AND_BR_EDR_HOST = 0x10,
};

struct Advertiser {
  os::Handler* handler;
  AddressWithType current_address;
  common::Callback<void(Address, AddressType)> scan_callback;
  common::Callback<void(ErrorCode, uint8_t, uint8_t)> set_terminated_callback;
  int8_t tx_power;
  uint16_t duration;
  uint8_t max_extended_advertising_events;
  bool started = false;
  bool connectable = false;
  std::unique_ptr<os::Alarm> address_rotation_alarm;
};

ExtendedAdvertisingConfig::ExtendedAdvertisingConfig(const AdvertisingConfig& config) : AdvertisingConfig(config) {
  switch (config.advertising_type) {
    case AdvertisingType::ADV_IND:
      connectable = true;
      scannable = true;
      break;
    case AdvertisingType::ADV_DIRECT_IND:
      connectable = true;
      directed = true;
      high_duty_directed_connectable = true;
      break;
    case AdvertisingType::ADV_SCAN_IND:
      scannable = true;
      break;
    case AdvertisingType::ADV_NONCONN_IND:
      break;
    case AdvertisingType::ADV_DIRECT_IND_LOW:
      connectable = true;
      directed = true;
      break;
    default:
      LOG_WARN("Unknown event type");
      break;
  }
}

struct LeAdvertisingManager::impl : public bluetooth::hci::LeAddressManagerCallback {
  impl(Module* module) : module_(module), le_advertising_interface_(nullptr), num_instances_(0) {}

  ~impl() {
    if (address_manager_registered) {
      le_address_manager_->Unregister(this);
    }
    advertising_sets_.clear();
  }

  void start(os::Handler* handler, hci::HciLayer* hci_layer, hci::Controller* controller,
             hci::AclManager* acl_manager) {
    module_handler_ = handler;
    hci_layer_ = hci_layer;
    controller_ = controller;
    le_maximum_advertising_data_length_ = controller_->GetLeMaximumAdvertisingDataLength();
    le_address_manager_ = acl_manager->GetLeAddressManager();
    le_advertising_interface_ =
        hci_layer_->GetLeAdvertisingInterface(module_handler_->BindOn(this, &LeAdvertisingManager::impl::handle_event));
    num_instances_ = controller_->GetLeNumberOfSupportedAdverisingSets();
    enabled_sets_ = std::vector<EnabledSet>(num_instances_);
    for (size_t i = 0; i < enabled_sets_.size(); i++) {
      enabled_sets_[i].advertising_handle_ = kInvalidHandle;
    }

    if (controller_->IsSupported(hci::OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS)) {
      advertising_api_type_ = AdvertisingApiType::EXTENDED;
    } else if (controller_->IsSupported(hci::OpCode::LE_MULTI_ADVT)) {
      advertising_api_type_ = AdvertisingApiType::ANDROID_HCI;
    } else {
      advertising_api_type_ = AdvertisingApiType::LEGACY;
      hci_layer_->EnqueueCommand(
          LeReadAdvertisingPhysicalChannelTxPowerBuilder::Create(),
          handler->BindOnceOn(this, &impl::on_read_advertising_physical_channel_tx_power));
    }
  }

  size_t GetNumberOfAdvertisingInstances() const {
    return num_instances_;
  }

  AdvertisingApiType get_advertising_api_type() const {
    return advertising_api_type_;
  }

  void register_advertising_callback(AdvertisingCallback* advertising_callback) {
    advertising_callbacks_ = advertising_callback;
  }

  void register_set_terminated_callback(
      common::ContextualCallback<void(ErrorCode, uint16_t, hci::AddressWithType)> set_terminated_callback) {
    set_terminated_callback_ = std::move(set_terminated_callback);
  }

  void handle_event(LeMetaEventView event) {
    switch (event.GetSubeventCode()) {
      case hci::SubeventCode::SCAN_REQUEST_RECEIVED:
        handle_scan_request(LeScanRequestReceivedView::Create(event));
        break;
      case hci::SubeventCode::ADVERTISING_SET_TERMINATED:
        handle_set_terminated(LeAdvertisingSetTerminatedView::Create(event));
        break;
      default:
        LOG_INFO("Unknown subevent in scanner %s", hci::SubeventCodeText(event.GetSubeventCode()).c_str());
    }
  }

  void handle_scan_request(LeScanRequestReceivedView event_view) {
    if (!event_view.IsValid()) {
      LOG_INFO("Dropping invalid scan request event");
      return;
    }
    registered_handler_->Post(
        common::BindOnce(scan_callback_, event_view.GetScannerAddress(), event_view.GetScannerAddressType()));
  }

  void handle_set_terminated(LeAdvertisingSetTerminatedView event_view) {
    if (!event_view.IsValid()) {
      LOG_INFO("Dropping invalid advertising event");
      return;
    }

    uint8_t advertiser_id = event_view.GetAdvertisingHandle();

    if (advertising_sets_[advertiser_id].address_rotation_alarm != nullptr) {
      advertising_sets_[advertiser_id].address_rotation_alarm->Cancel();
      advertising_sets_[advertiser_id].address_rotation_alarm.reset();
    }
    enabled_sets_[advertiser_id].advertising_handle_ = kInvalidHandle;

    AddressWithType advertiser_address = advertising_sets_[event_view.GetAdvertisingHandle()].current_address;

    set_terminated_callback_.InvokeIfNotEmpty(
        event_view.GetStatus(), event_view.GetConnectionHandle(), advertiser_address);
  }

  AdvertiserId allocate_advertiser() {
    AdvertiserId id = 0;
    {
      std::unique_lock lock(id_mutex_);
      while (id < num_instances_ && advertising_sets_.count(id) != 0) {
        id++;
      }
    }
    if (id == num_instances_) {
      return kInvalidId;
    }
    return id;
  }

  void remove_advertiser(AdvertiserId advertiser_id) {
    stop_advertising(advertiser_id);
    std::unique_lock lock(id_mutex_);
    if (advertising_sets_.count(advertiser_id) == 0) {
      return;
    }
    advertising_sets_.erase(advertiser_id);
    if (advertising_sets_.empty() && address_manager_registered) {
      le_address_manager_->Unregister(this);
      address_manager_registered = false;
      paused = false;
    }
    if (advertising_api_type_ == AdvertisingApiType::EXTENDED) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeRemoveAdvertisingSetBuilder::Create(advertiser_id),
          module_handler_->BindOnce(impl::check_status<LeRemoveAdvertisingSetCompleteView>));

      if (advertising_sets_[advertiser_id].address_rotation_alarm != nullptr) {
        advertising_sets_[advertiser_id].address_rotation_alarm->Cancel();
        advertising_sets_[advertiser_id].address_rotation_alarm.reset();
      }
    }
  }

  void create_advertiser(
      AdvertiserId id,
      const AdvertisingConfig config,
      const common::Callback<void(Address, AddressType)>& scan_callback,
      const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
      os::Handler* handler) {
    advertising_sets_[id].scan_callback = scan_callback;
    advertising_sets_[id].set_terminated_callback = set_terminated_callback;
    advertising_sets_[id].handler = handler;
    advertising_sets_[id].current_address = AddressWithType{};

    if (!address_manager_registered) {
      le_address_manager_->Register(this);
      address_manager_registered = true;
    }

    switch (advertising_api_type_) {
      case (AdvertisingApiType::LEGACY): {
        set_parameters(id, config);
        if (config.advertising_type == AdvertisingType::ADV_IND ||
            config.advertising_type == AdvertisingType::ADV_NONCONN_IND) {
          set_data(id, true, config.scan_response);
        }
        set_data(id, false, config.advertisement);
        if (!paused) {
          enable_advertiser(id, true, 0, 0);
        } else {
          enabled_sets_[id].advertising_handle_ = id;
        }
      } break;
      case (AdvertisingApiType::ANDROID_HCI): {
        set_parameters(id, config);
        if (config.advertising_type == AdvertisingType::ADV_IND ||
            config.advertising_type == AdvertisingType::ADV_NONCONN_IND) {
          set_data(id, true, config.scan_response);
        }
        set_data(id, false, config.advertisement);
        advertising_sets_[id].current_address = le_address_manager_->GetAnotherAddress();
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtSetRandomAddrBuilder::Create(advertising_sets_[id].current_address.GetAddress(), id),
            module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        if (!paused) {
          enable_advertiser(id, true, 0, 0);
        } else {
          enabled_sets_[id].advertising_handle_ = id;
        }
      } break;
      case (AdvertisingApiType::EXTENDED): {
        LOG_WARN("Unexpected AdvertisingApiType EXTENDED");
      } break;
    }
  }

  void create_extended_advertiser(
      int reg_id,
      AdvertiserId id,
      const ExtendedAdvertisingConfig config,
      const common::Callback<void(Address, AddressType)>& scan_callback,
      const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
      uint16_t duration,
      uint8_t max_ext_adv_events,
      os::Handler* handler) {
    id_map_[id] = reg_id;

    if (advertising_api_type_ != AdvertisingApiType::EXTENDED) {
      create_advertiser(id, config, scan_callback, set_terminated_callback, handler);
      return;
    }

    advertising_sets_[id].scan_callback = scan_callback;
    advertising_sets_[id].set_terminated_callback = set_terminated_callback;
    advertising_sets_[id].duration = duration;
    advertising_sets_[id].max_extended_advertising_events = max_ext_adv_events;
    advertising_sets_[id].handler = handler;

    set_parameters(id, config);

    auto address_policy = le_address_manager_->GetAddressPolicy();
    if (config.own_address_type == OwnAddressType::RANDOM_DEVICE_ADDRESS) {
      if (address_policy == LeAddressManager::AddressPolicy::USE_NON_RESOLVABLE_ADDRESS ||
          address_policy == LeAddressManager::AddressPolicy::USE_RESOLVABLE_ADDRESS) {
        AddressWithType address_with_type = le_address_manager_->GetAnotherAddress();
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingRandomAddressBuilder::Create(id, address_with_type.GetAddress()),
            module_handler_->BindOnceOn(
                this,
                &impl::on_set_advertising_set_random_address_complete<
                    LeSetExtendedAdvertisingRandomAddressCompleteView>,
                id,
                address_with_type));

        // start timer for random address
        advertising_sets_[id].address_rotation_alarm = std::make_unique<os::Alarm>(module_handler_);
        advertising_sets_[id].address_rotation_alarm->Schedule(
            common::BindOnce(&impl::set_advertising_set_random_address, common::Unretained(this), id),
            le_address_manager_->GetNextPrivateAddressIntervalMs());
      } else {
        advertising_sets_[id].current_address = le_address_manager_->GetCurrentAddress();
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingRandomAddressBuilder::Create(
                id, advertising_sets_[id].current_address.GetAddress()),
            module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingRandomAddressCompleteView>));
      }
    } else {
      advertising_sets_[id].current_address =
          AddressWithType(controller_->GetMacAddress(), AddressType::PUBLIC_DEVICE_ADDRESS);
    }
    if (config.advertising_type == AdvertisingType::ADV_IND ||
        config.advertising_type == AdvertisingType::ADV_NONCONN_IND) {
      set_data(id, true, config.scan_response);
    }
    set_data(id, false, config.advertisement);

    if (!config.periodic_data.empty()) {
      set_periodic_parameter(id, config.periodic_advertising_parameters);
      set_periodic_data(id, config.periodic_data);
      enable_periodic_advertising(id, true);
    }

    if (!paused) {
      enable_advertiser(id, true, duration, max_ext_adv_events);
    } else {
      EnabledSet curr_set;
      curr_set.advertising_handle_ = id;
      curr_set.duration_ = duration;
      curr_set.max_extended_advertising_events_ = max_ext_adv_events;
      std::vector<EnabledSet> enabled_sets = {curr_set};
      enabled_sets_[id] = curr_set;
    }
  }

  void stop_advertising(AdvertiserId advertiser_id) {
    if (advertising_sets_.find(advertiser_id) == advertising_sets_.end()) {
      LOG_INFO("Unknown advertising set %u", advertiser_id);
      return;
    }
    EnabledSet curr_set;
    curr_set.advertising_handle_ = advertiser_id;
    std::vector<EnabledSet> enabled_vector{curr_set};

    // If advertising or periodic advertising on the advertising set is enabled,
    // then the Controller will return the error code Command Disallowed (0x0C).
    // Thus, we should disable it before removing it.
    switch (advertising_api_type_) {
      case (AdvertisingApiType::LEGACY):
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetAdvertisingEnableBuilder::Create(Enable::DISABLED),
            module_handler_->BindOnce(impl::check_status<LeSetAdvertisingEnableCompleteView>));
        break;
      case (AdvertisingApiType::ANDROID_HCI):
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtSetEnableBuilder::Create(Enable::DISABLED, advertiser_id),
            module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        break;
      case (AdvertisingApiType::EXTENDED): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::DISABLED, enabled_vector),
            module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingEnableCompleteView>));

        le_advertising_interface_->EnqueueCommand(
            hci::LeSetPeriodicAdvertisingEnableBuilder::Create(Enable::DISABLED, advertiser_id),
            module_handler_->BindOnce(impl::check_status<LeSetPeriodicAdvertisingEnableCompleteView>));
      } break;
    }

    std::unique_lock lock(id_mutex_);
    enabled_sets_[advertiser_id].advertising_handle_ = kInvalidHandle;
  }

  void set_advertising_set_random_address(AdvertiserId advertiser_id) {
    // This function should only be trigger by enabled advertising set
    if (enabled_sets_[advertiser_id].advertising_handle_ == kInvalidHandle) {
      if (advertising_sets_[advertiser_id].address_rotation_alarm != nullptr) {
        advertising_sets_[advertiser_id].address_rotation_alarm->Cancel();
        advertising_sets_[advertiser_id].address_rotation_alarm.reset();
      }
      return;
    }

    // TODO handle duration and max_extended_advertising_events_
    EnabledSet curr_set;
    curr_set.advertising_handle_ = advertiser_id;
    curr_set.duration_ = advertising_sets_[advertiser_id].duration;
    curr_set.max_extended_advertising_events_ = advertising_sets_[advertiser_id].max_extended_advertising_events;
    std::vector<EnabledSet> enabled_sets = {curr_set};

    // For connectable advertising, we should disable it first
    if (advertising_sets_[advertiser_id].connectable) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::DISABLED, enabled_sets),
          module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingEnableCompleteView>));
    }

    AddressWithType address_with_type = le_address_manager_->GetAnotherAddress();
    le_advertising_interface_->EnqueueCommand(
        hci::LeSetExtendedAdvertisingRandomAddressBuilder::Create(advertiser_id, address_with_type.GetAddress()),
        module_handler_->BindOnceOn(
            this,
            &impl::on_set_advertising_set_random_address_complete<LeSetExtendedAdvertisingRandomAddressCompleteView>,
            advertiser_id,
            address_with_type));

    if (advertising_sets_[advertiser_id].connectable) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::ENABLED, enabled_sets),
          module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingEnableCompleteView>));
    }

    advertising_sets_[advertiser_id].address_rotation_alarm->Schedule(
        common::BindOnce(&impl::set_advertising_set_random_address, common::Unretained(this), advertiser_id),
        le_address_manager_->GetNextPrivateAddressIntervalMs());
  }

  void set_parameters(AdvertiserId advertiser_id, ExtendedAdvertisingConfig config) {
    advertising_sets_[advertiser_id].connectable = config.connectable;

    switch (advertising_api_type_) {
      case (AdvertisingApiType::LEGACY): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetAdvertisingParametersBuilder::Create(
                config.interval_min,
                config.interval_max,
                config.advertising_type,
                config.own_address_type,
                config.peer_address_type,
                config.peer_address,
                config.channel_map,
                config.filter_policy),
            module_handler_->BindOnceOn(
                this, &impl::check_status_with_id<LeSetAdvertisingParametersCompleteView>, advertiser_id));
      } break;
      case (AdvertisingApiType::ANDROID_HCI): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtParamBuilder::Create(
                config.interval_min,
                config.interval_max,
                config.advertising_type,
                config.own_address_type,
                config.peer_address_type,
                config.peer_address,
                config.channel_map,
                config.filter_policy,
                advertiser_id,
                config.tx_power),
            module_handler_->BindOnceOn(this, &impl::check_status_with_id<LeMultiAdvtCompleteView>, advertiser_id));
      } break;
      case (AdvertisingApiType::EXTENDED): {
        // sid must be in range 0x00 to 0x0F. Since no controller supports more than
        // 16 advertisers, it's safe to make sid equal to id.
        config.sid = advertiser_id % kAdvertisingSetIdMask;

        if (config.legacy_pdus) {
          LegacyAdvertisingProperties legacy_properties = LegacyAdvertisingProperties::ADV_IND;
          if (config.connectable && config.directed) {
            if (config.high_duty_directed_connectable) {
              legacy_properties = LegacyAdvertisingProperties::ADV_DIRECT_IND_HIGH;
            } else {
              legacy_properties = LegacyAdvertisingProperties::ADV_DIRECT_IND_LOW;
            }
          }
          if (config.scannable && !config.connectable) {
            legacy_properties = LegacyAdvertisingProperties::ADV_SCAN_IND;
          }
          if (!config.scannable && !config.connectable) {
            legacy_properties = LegacyAdvertisingProperties::ADV_NONCONN_IND;
          }

          le_advertising_interface_->EnqueueCommand(
              LeSetExtendedAdvertisingLegacyParametersBuilder::Create(
                  advertiser_id,
                  legacy_properties,
                  config.interval_min,
                  config.interval_max,
                  config.channel_map,
                  config.own_address_type,
                  config.peer_address_type,
                  config.peer_address,
                  config.filter_policy,
                  config.tx_power,
                  config.sid,
                  config.enable_scan_request_notifications),
              module_handler_->BindOnceOn(
                  this,
                  &impl::on_set_extended_advertising_parameters_complete<
                      LeSetExtendedAdvertisingParametersCompleteView>,
                  advertiser_id));
        } else {
          uint8_t legacy_properties = (config.connectable ? 0x1 : 0x00) | (config.scannable ? 0x2 : 0x00) |
                                      (config.directed ? 0x4 : 0x00) |
                                      (config.high_duty_directed_connectable ? 0x8 : 0x00);
          uint8_t extended_properties = (config.anonymous ? 0x20 : 0x00) | (config.include_tx_power ? 0x40 : 0x00);
          extended_properties = extended_properties >> 5;

          le_advertising_interface_->EnqueueCommand(
              hci::LeSetExtendedAdvertisingParametersBuilder::Create(
                  advertiser_id,
                  legacy_properties,
                  extended_properties,
                  config.interval_min,
                  config.interval_max,
                  config.channel_map,
                  config.own_address_type,
                  config.peer_address_type,
                  config.peer_address,
                  config.filter_policy,
                  config.tx_power,
                  (config.use_le_coded_phy ? PrimaryPhyType::LE_CODED : PrimaryPhyType::LE_1M),
                  config.secondary_max_skip,
                  config.secondary_advertising_phy,
                  config.sid,
                  config.enable_scan_request_notifications),
              module_handler_->BindOnceOn(
                  this,
                  &impl::on_set_extended_advertising_parameters_complete<
                      LeSetExtendedAdvertisingParametersCompleteView>,
                  advertiser_id));
        }
      } break;
    }
  }

  void set_data(AdvertiserId advertiser_id, bool set_scan_rsp, std::vector<GapData> data) {
    if (!set_scan_rsp && advertising_sets_[advertiser_id].connectable) {
      GapData gap_data;
      gap_data.data_type_ = GapDataType::FLAGS;
      if (advertising_sets_[advertiser_id].duration == 0) {
        gap_data.data_.push_back(static_cast<uint8_t>(AdvertisingFlag::LE_GENERAL_DISCOVERABLE));
      } else {
        gap_data.data_.push_back(static_cast<uint8_t>(AdvertisingFlag::LE_LIMITED_DISCOVERABLE));
      }
      data.insert(data.begin(), gap_data);
    }

    switch (advertising_api_type_) {
      case (AdvertisingApiType::LEGACY): {
        if (set_scan_rsp) {
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetScanResponseDataBuilder::Create(data),
              module_handler_->BindOnceOn(
                  this, &impl::check_status_with_id<LeSetScanResponseDataCompleteView>, advertiser_id));
        } else {
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetAdvertisingDataBuilder::Create(data),
              module_handler_->BindOnceOn(
                  this, &impl::check_status_with_id<LeSetAdvertisingDataCompleteView>, advertiser_id));
        }
      } break;
      case (AdvertisingApiType::ANDROID_HCI): {
        if (set_scan_rsp) {
          le_advertising_interface_->EnqueueCommand(
              hci::LeMultiAdvtSetScanRespBuilder::Create(data, advertiser_id),
              module_handler_->BindOnceOn(this, &impl::check_status_with_id<LeMultiAdvtCompleteView>, advertiser_id));
        } else {
          le_advertising_interface_->EnqueueCommand(
              hci::LeMultiAdvtSetDataBuilder::Create(data, advertiser_id),
              module_handler_->BindOnceOn(this, &impl::check_status_with_id<LeMultiAdvtCompleteView>, advertiser_id));
        }
      } break;
      case (AdvertisingApiType::EXTENDED): {
        uint16_t data_len = 0;
        // check data size
        for (int i = 0; i < data.size(); i++) {
          if (data[i].size() > kLeMaximumFragmentLength) {
            LOG_WARN("AD data len shall not greater than %d", kLeMaximumFragmentLength);
            if (advertising_callbacks_ != nullptr) {
              if (set_scan_rsp) {
                advertising_callbacks_->OnScanResponseDataSet(
                    advertiser_id, AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR);
              } else {
                advertising_callbacks_->OnAdvertisingDataSet(
                    advertiser_id, AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR);
              }
            }
            return;
          }
          data_len += data[i].size();
        }

        if (data_len > le_maximum_advertising_data_length_) {
          LOG_WARN(
              "advertising data len exceeds le_maximum_advertising_data_length_ %d",
              le_maximum_advertising_data_length_);
          if (advertising_callbacks_ != nullptr) {
            if (set_scan_rsp) {
              advertising_callbacks_->OnScanResponseDataSet(
                  advertiser_id, AdvertisingCallback::AdvertisingStatus::DATA_TOO_LARGE);
            } else {
              advertising_callbacks_->OnAdvertisingDataSet(
                  advertiser_id, AdvertisingCallback::AdvertisingStatus::DATA_TOO_LARGE);
            }
          }
          return;
        }

        if (data_len <= kLeMaximumFragmentLength) {
          send_data_fragment(advertiser_id, set_scan_rsp, data, Operation::COMPLETE_ADVERTISEMENT);
        } else {
          std::vector<GapData> sub_data;
          uint16_t sub_data_len = 0;
          Operation operation = Operation::FIRST_FRAGMENT;

          for (int i = 0; i < data.size(); i++) {
            if (sub_data_len + data[i].size() > kLeMaximumFragmentLength) {
              send_data_fragment(advertiser_id, set_scan_rsp, sub_data, operation);
              operation = Operation::INTERMEDIATE_FRAGMENT;
              sub_data_len = 0;
              sub_data.clear();
            }
            sub_data.push_back(data[i]);
            sub_data_len += data[i].size();
          }
          send_data_fragment(advertiser_id, set_scan_rsp, sub_data, Operation::LAST_FRAGMENT);
        }
      } break;
    }
  }

  void send_data_fragment(
      AdvertiserId advertiser_id, bool set_scan_rsp, std::vector<GapData> data, Operation operation) {
    if (operation == Operation::COMPLETE_ADVERTISEMENT || operation == Operation::LAST_FRAGMENT) {
      if (set_scan_rsp) {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingScanResponseBuilder::Create(
                advertiser_id, operation, kFragment_preference, data),
            module_handler_->BindOnceOn(
                this, &impl::check_status_with_id<LeSetExtendedAdvertisingScanResponseCompleteView>, advertiser_id));
      } else {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingDataBuilder::Create(advertiser_id, operation, kFragment_preference, data),
            module_handler_->BindOnceOn(
                this, &impl::check_status_with_id<LeSetExtendedAdvertisingDataCompleteView>, advertiser_id));
      }
    } else {
      // For first and intermediate fragment, do not trigger advertising_callbacks_.
      if (set_scan_rsp) {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingScanResponseBuilder::Create(
                advertiser_id, operation, kFragment_preference, data),
            module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingScanResponseCompleteView>));
      } else {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingDataBuilder::Create(advertiser_id, operation, kFragment_preference, data),
            module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingDataCompleteView>));
      }
    }
  }

  void enable_advertiser(
      AdvertiserId advertiser_id, bool enable, uint16_t duration, uint8_t max_extended_advertising_events) {
    EnabledSet curr_set;
    curr_set.advertising_handle_ = advertiser_id;
    curr_set.duration_ = duration;
    curr_set.max_extended_advertising_events_ = max_extended_advertising_events;
    std::vector<EnabledSet> enabled_sets = {curr_set};
    Enable enable_value = enable ? Enable::ENABLED : Enable::DISABLED;

    switch (advertising_api_type_) {
      case (AdvertisingApiType::LEGACY): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetAdvertisingEnableBuilder::Create(enable_value),
            module_handler_->BindOnceOn(
                this,
                &impl::on_set_advertising_enable_complete<LeSetAdvertisingEnableCompleteView>,
                enable,
                enabled_sets));
      } break;
      case (AdvertisingApiType::ANDROID_HCI): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtSetEnableBuilder::Create(enable_value, advertiser_id),
            module_handler_->BindOnceOn(
                this, &impl::on_set_advertising_enable_complete<LeMultiAdvtCompleteView>, enable, enabled_sets));
      } break;
      case (AdvertisingApiType::EXTENDED): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingEnableBuilder::Create(enable_value, enabled_sets),
            module_handler_->BindOnceOn(
                this,
                &impl::on_set_extended_advertising_enable_complete<LeSetExtendedAdvertisingEnableCompleteView>,
                enable,
                enabled_sets));
      } break;
    }

    if (enable) {
      enabled_sets_[advertiser_id].advertising_handle_ = advertiser_id;
      advertising_sets_[advertiser_id].duration = duration;
      advertising_sets_[advertiser_id].max_extended_advertising_events = max_extended_advertising_events;
    } else {
      enabled_sets_[advertiser_id].advertising_handle_ = kInvalidHandle;
      if (advertising_sets_[advertiser_id].address_rotation_alarm != nullptr) {
        advertising_sets_[advertiser_id].address_rotation_alarm->Cancel();
        advertising_sets_[advertiser_id].address_rotation_alarm.reset();
      }
    }
  }

  void set_periodic_parameter(
      AdvertiserId advertiser_id, PeriodicAdvertisingParameters periodic_advertising_parameters) {
    uint8_t include_tx_power = periodic_advertising_parameters.properties >>
                               PeriodicAdvertisingParameters::AdvertisingProperty::INCLUDE_TX_POWER;

    le_advertising_interface_->EnqueueCommand(
        hci::LeSetPeriodicAdvertisingParamBuilder::Create(
            advertiser_id,
            periodic_advertising_parameters.min_interval,
            periodic_advertising_parameters.max_interval,
            include_tx_power),
        module_handler_->BindOnceOn(
            this, &impl::check_status_with_id<LeSetPeriodicAdvertisingParamCompleteView>, advertiser_id));
  }

  void set_periodic_data(AdvertiserId advertiser_id, std::vector<GapData> data) {
    uint16_t data_len = 0;
    // check data size
    for (int i = 0; i < data.size(); i++) {
      if (data[i].size() > kLeMaximumFragmentLength) {
        LOG_WARN("AD data len shall not greater than %d", kLeMaximumFragmentLength);
        if (advertising_callbacks_ != nullptr) {
          advertising_callbacks_->OnPeriodicAdvertisingDataSet(
              advertiser_id, AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR);
        }
        return;
      }
      data_len += data[i].size();
    }

    if (data_len > le_maximum_advertising_data_length_) {
      LOG_WARN(
          "advertising data len exceeds le_maximum_advertising_data_length_ %d", le_maximum_advertising_data_length_);
      if (advertising_callbacks_ != nullptr) {
        advertising_callbacks_->OnPeriodicAdvertisingDataSet(
            advertiser_id, AdvertisingCallback::AdvertisingStatus::DATA_TOO_LARGE);
      }
      return;
    }

    if (data_len <= kLeMaximumFragmentLength) {
      send_periodic_data_fragment(advertiser_id, data, Operation::COMPLETE_ADVERTISEMENT);
    } else {
      std::vector<GapData> sub_data;
      uint16_t sub_data_len = 0;
      Operation operation = Operation::FIRST_FRAGMENT;

      for (int i = 0; i < data.size(); i++) {
        if (sub_data_len + data[i].size() > kLeMaximumFragmentLength) {
          send_periodic_data_fragment(advertiser_id, sub_data, operation);
          operation = Operation::INTERMEDIATE_FRAGMENT;
          sub_data_len = 0;
          sub_data.clear();
        }
        sub_data.push_back(data[i]);
        sub_data_len += data[i].size();
      }
      send_periodic_data_fragment(advertiser_id, sub_data, Operation::LAST_FRAGMENT);
    }
  }

  void send_periodic_data_fragment(AdvertiserId advertiser_id, std::vector<GapData> data, Operation operation) {
    if (operation == Operation::COMPLETE_ADVERTISEMENT || operation == Operation::LAST_FRAGMENT) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetPeriodicAdvertisingDataBuilder::Create(advertiser_id, operation, data),
          module_handler_->BindOnceOn(
              this, &impl::check_status_with_id<LeSetPeriodicAdvertisingDataCompleteView>, advertiser_id));
    } else {
      // For first and intermediate fragment, do not trigger advertising_callbacks_.
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetPeriodicAdvertisingDataBuilder::Create(advertiser_id, operation, data),
          module_handler_->BindOnce(impl::check_status<LeSetPeriodicAdvertisingDataCompleteView>));
    }
  }

  void enable_periodic_advertising(AdvertiserId advertiser_id, bool enable) {
    Enable enable_value = enable ? Enable::ENABLED : Enable::DISABLED;

    le_advertising_interface_->EnqueueCommand(
        hci::LeSetPeriodicAdvertisingEnableBuilder::Create(enable_value, advertiser_id),
        module_handler_->BindOnceOn(
            this,
            &impl::on_set_periodic_advertising_enable_complete<LeSetPeriodicAdvertisingEnableCompleteView>,
            enable,
            advertiser_id));
  }

  void OnPause() override {
    paused = true;
    if (!advertising_sets_.empty()) {
      std::vector<EnabledSet> enabled_sets = {};
      for (size_t i = 0; i < enabled_sets_.size(); i++) {
        EnabledSet curr_set = enabled_sets_[i];
        if (enabled_sets_[i].advertising_handle_ != kInvalidHandle) {
          enabled_sets.push_back(enabled_sets_[i]);
        }
      }

      switch (advertising_api_type_) {
        case (AdvertisingApiType::LEGACY): {
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetAdvertisingEnableBuilder::Create(Enable::DISABLED),
              module_handler_->BindOnceOn(
                  this,
                  &impl::on_set_advertising_enable_complete<LeSetAdvertisingEnableCompleteView>,
                  false,
                  enabled_sets));
        } break;
        case (AdvertisingApiType::ANDROID_HCI): {
          for (size_t i = 0; i < enabled_sets_.size(); i++) {
            uint8_t id = enabled_sets_[i].advertising_handle_;
            if (id != kInvalidHandle) {
              le_advertising_interface_->EnqueueCommand(
                  hci::LeMultiAdvtSetEnableBuilder::Create(Enable::DISABLED, id),
                  module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
            }
          }
        } break;
        case (AdvertisingApiType::EXTENDED): {
          if (enabled_sets.size() != 0) {
            le_advertising_interface_->EnqueueCommand(
                hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::DISABLED, enabled_sets),
                module_handler_->BindOnceOn(
                    this,
                    &impl::on_set_extended_advertising_enable_complete<LeSetExtendedAdvertisingEnableCompleteView>,
                    false,
                    enabled_sets));
          }
        } break;
      }
    }
    le_address_manager_->AckPause(this);
  }

  void OnResume() override {
    paused = false;
    if (!advertising_sets_.empty()) {
      std::vector<EnabledSet> enabled_sets = {};
      for (size_t i = 0; i < enabled_sets_.size(); i++) {
        EnabledSet curr_set = enabled_sets_[i];
        if (enabled_sets_[i].advertising_handle_ != kInvalidHandle) {
          enabled_sets.push_back(enabled_sets_[i]);
        }
      }

      switch (advertising_api_type_) {
        case (AdvertisingApiType::LEGACY): {
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetAdvertisingEnableBuilder::Create(Enable::ENABLED),
              module_handler_->BindOnceOn(
                  this,
                  &impl::on_set_advertising_enable_complete<LeSetAdvertisingEnableCompleteView>,
                  true,
                  enabled_sets));
        } break;
        case (AdvertisingApiType::ANDROID_HCI): {
          for (size_t i = 0; i < enabled_sets_.size(); i++) {
            uint8_t id = enabled_sets_[i].advertising_handle_;
            if (id != kInvalidHandle) {
              le_advertising_interface_->EnqueueCommand(
                  hci::LeMultiAdvtSetEnableBuilder::Create(Enable::ENABLED, id),
                  module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
            }
          }
        } break;
        case (AdvertisingApiType::EXTENDED): {
          if (enabled_sets.size() != 0) {
            le_advertising_interface_->EnqueueCommand(
                hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::ENABLED, enabled_sets),
                module_handler_->BindOnceOn(
                    this,
                    &impl::on_set_extended_advertising_enable_complete<LeSetExtendedAdvertisingEnableCompleteView>,
                    true,
                    enabled_sets));
          }
        } break;
      }
    }
    le_address_manager_->AckResume(this);
  }

  common::Callback<void(Address, AddressType)> scan_callback_;
  common::ContextualCallback<void(ErrorCode, uint16_t, hci::AddressWithType)> set_terminated_callback_{};
  AdvertisingCallback* advertising_callbacks_ = nullptr;
  os::Handler* registered_handler_{nullptr};
  Module* module_;
  os::Handler* module_handler_;
  hci::HciLayer* hci_layer_;
  hci::Controller* controller_;
  uint16_t le_maximum_advertising_data_length_;
  int8_t le_physical_channel_tx_power_ = 0;
  hci::LeAdvertisingInterface* le_advertising_interface_;
  std::map<AdvertiserId, Advertiser> advertising_sets_;
  hci::LeAddressManager* le_address_manager_;
  bool address_manager_registered = false;
  bool paused = false;

  std::mutex id_mutex_;
  size_t num_instances_;
  std::vector<hci::EnabledSet> enabled_sets_;
  std::map<uint8_t, int> id_map_;

  AdvertisingApiType advertising_api_type_{0};

  void on_read_advertising_physical_channel_tx_power(CommandCompleteView view) {
    auto complete_view = LeReadAdvertisingPhysicalChannelTxPowerCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
      return;
    }
    le_physical_channel_tx_power_ = complete_view.GetTransmitPowerLevel();
  }

  template <class View>
  void on_set_advertising_enable_complete(bool enable, std::vector<EnabledSet> enabled_sets, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto complete_view = View::Create(view);
    ASSERT(complete_view.IsValid());
    AdvertisingCallback::AdvertisingStatus advertising_status = AdvertisingCallback::AdvertisingStatus::SUCCESS;
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
    }

    if (advertising_callbacks_ == nullptr) {
      return;
    }
    for (EnabledSet enabled_set : enabled_sets) {
      bool started = advertising_sets_[enabled_set.advertising_handle_].started;
      uint8_t id = enabled_set.advertising_handle_;
      if (id == kInvalidHandle) {
        continue;
      }

      if (started) {
        advertising_callbacks_->OnAdvertisingEnabled(id, enable, advertising_status);
      } else {
        int reg_id = id_map_[id];
        advertising_sets_[enabled_set.advertising_handle_].started = true;
        advertising_callbacks_->OnAdvertisingSetStarted(reg_id, id, le_physical_channel_tx_power_, advertising_status);
      }
    }
  }

  template <class View>
  void on_set_extended_advertising_enable_complete(
      bool enable, std::vector<EnabledSet> enabled_sets, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto complete_view = LeSetExtendedAdvertisingEnableCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    AdvertisingCallback::AdvertisingStatus advertising_status = AdvertisingCallback::AdvertisingStatus::SUCCESS;
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
      advertising_status = AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR;
    }

    if (advertising_callbacks_ == nullptr) {
      return;
    }

    for (EnabledSet enabled_set : enabled_sets) {
      int8_t tx_power = advertising_sets_[enabled_set.advertising_handle_].tx_power;
      bool started = advertising_sets_[enabled_set.advertising_handle_].started;
      uint8_t id = enabled_set.advertising_handle_;
      if (id == kInvalidHandle) {
        continue;
      }

      if (started) {
        advertising_callbacks_->OnAdvertisingEnabled(id, enable, advertising_status);
      } else {
        int reg_id = id_map_[id];
        advertising_sets_[enabled_set.advertising_handle_].started = true;
        advertising_callbacks_->OnAdvertisingSetStarted(reg_id, id, tx_power, advertising_status);
      }
    }
  }

  template <class View>
  void on_set_extended_advertising_parameters_complete(AdvertiserId id, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto complete_view = LeSetExtendedAdvertisingParametersCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    AdvertisingCallback::AdvertisingStatus advertising_status = AdvertisingCallback::AdvertisingStatus::SUCCESS;
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
      advertising_status = AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR;
    }
    advertising_sets_[id].tx_power = complete_view.GetSelectedTxPower();

    if (advertising_sets_[id].started) {
      advertising_callbacks_->OnAdvertisingParametersUpdated(id, advertising_sets_[id].tx_power, advertising_status);
    }
  }

  template <class View>
  void on_set_periodic_advertising_enable_complete(bool enable, AdvertiserId id, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto complete_view = LeSetPeriodicAdvertisingEnableCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    AdvertisingCallback::AdvertisingStatus advertising_status = AdvertisingCallback::AdvertisingStatus::SUCCESS;
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
      advertising_status = AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR;
    }

    if (advertising_callbacks_ == nullptr || !advertising_sets_[id].started) {
      return;
    }

    advertising_callbacks_->OnPeriodicAdvertisingEnabled(id, enable, advertising_status);
  }

  template <class View>
  void on_set_advertising_set_random_address_complete(
      AdvertiserId advertiser_id, AddressWithType address_with_type, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto complete_view = LeSetExtendedAdvertisingRandomAddressCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
    } else {
      LOG_INFO(
          "update random address for advertising set %d : %s",
          advertiser_id,
          address_with_type.GetAddress().ToString().c_str());
      advertising_sets_[advertiser_id].current_address = address_with_type;
    }
  }

  template <class View>
  void check_status_with_id(AdvertiserId id, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto status_view = View::Create(view);
    ASSERT(status_view.IsValid());
    if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO(
          "Got a Command complete %s, status %s",
          OpCodeText(view.GetCommandOpCode()).c_str(),
          ErrorCodeText(status_view.GetStatus()).c_str());
    }
    AdvertisingCallback::AdvertisingStatus advertising_status = AdvertisingCallback::AdvertisingStatus::SUCCESS;
    if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(status_view.GetStatus()).c_str());
      advertising_status = AdvertisingCallback::AdvertisingStatus::INTERNAL_ERROR;
    }

    // Do not trigger callback if the advertiser not stated yet
    if (advertising_callbacks_ == nullptr || !advertising_sets_[id].started) {
      return;
    }

    OpCode opcode = view.GetCommandOpCode();

    switch (opcode) {
      case OpCode::LE_SET_ADVERTISING_PARAMETERS:
        advertising_callbacks_->OnAdvertisingParametersUpdated(id, le_physical_channel_tx_power_, advertising_status);
        break;
      case OpCode::LE_SET_ADVERTISING_DATA:
      case OpCode::LE_SET_EXTENDED_ADVERTISING_DATA:
        advertising_callbacks_->OnAdvertisingDataSet(id, advertising_status);
        break;
      case OpCode::LE_SET_SCAN_RESPONSE_DATA:
      case OpCode::LE_SET_EXTENDED_ADVERTISING_SCAN_RESPONSE:
        advertising_callbacks_->OnScanResponseDataSet(id, advertising_status);
        break;
      case OpCode::LE_SET_PERIODIC_ADVERTISING_PARAM:
        advertising_callbacks_->OnPeriodicAdvertisingParametersUpdated(id, advertising_status);
        break;
      case OpCode::LE_SET_PERIODIC_ADVERTISING_DATA:
        advertising_callbacks_->OnPeriodicAdvertisingDataSet(id, advertising_status);
        break;
      case OpCode::LE_MULTI_ADVT: {
        auto command_view = LeMultiAdvtCompleteView::Create(view);
        ASSERT(command_view.IsValid());
        auto sub_opcode = command_view.GetSubCmd();
        switch (sub_opcode) {
          case SubOcf::SET_PARAM:
            advertising_callbacks_->OnAdvertisingParametersUpdated(
                id, le_physical_channel_tx_power_, advertising_status);
            break;
          case SubOcf::SET_DATA:
            advertising_callbacks_->OnAdvertisingDataSet(id, advertising_status);
            break;
          case SubOcf::SET_SCAN_RESP:
            advertising_callbacks_->OnScanResponseDataSet(id, advertising_status);
            break;
          default:
            LOG_WARN("Unexpected sub event type %s", SubOcfText(command_view.GetSubCmd()).c_str());
        }
      } break;
      default:
        LOG_WARN("Unexpected event type %s", OpCodeText(view.GetCommandOpCode()).c_str());
    }
  }

  template <class View>
  static void check_status(CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto status_view = View::Create(view);
    ASSERT(status_view.IsValid());
    if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO(
          "Got a Command complete %s, status %s",
          OpCodeText(view.GetCommandOpCode()).c_str(),
          ErrorCodeText(status_view.GetStatus()).c_str());
    }
  }
};

LeAdvertisingManager::LeAdvertisingManager() {
  pimpl_ = std::make_unique<impl>(this);
}

void LeAdvertisingManager::ListDependencies(ModuleList* list) {
  list->add<hci::HciLayer>();
  list->add<hci::Controller>();
  list->add<hci::AclManager>();
}

void LeAdvertisingManager::Start() {
  pimpl_->start(GetHandler(), GetDependency<hci::HciLayer>(), GetDependency<hci::Controller>(),
                GetDependency<AclManager>());
}

void LeAdvertisingManager::Stop() {
  pimpl_.reset();
}

std::string LeAdvertisingManager::ToString() const {
  return "Le Advertising Manager";
}

size_t LeAdvertisingManager::GetNumberOfAdvertisingInstances() const {
  return pimpl_->GetNumberOfAdvertisingInstances();
}

AdvertiserId LeAdvertisingManager::create_advertiser(
    const AdvertisingConfig config,
    const common::Callback<void(Address, AddressType)>& scan_callback,
    const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
    os::Handler* handler) {
  if (config.peer_address == Address::kEmpty) {
    if (config.own_address_type == hci::OwnAddressType::RESOLVABLE_OR_PUBLIC_ADDRESS ||
        config.own_address_type == hci::OwnAddressType::RESOLVABLE_OR_RANDOM_ADDRESS) {
      LOG_WARN("Peer address can not be empty");
      return kInvalidId;
    }
    if (config.advertising_type == hci::AdvertisingType::ADV_DIRECT_IND ||
        config.advertising_type == hci::AdvertisingType::ADV_DIRECT_IND_LOW) {
      LOG_WARN("Peer address can not be empty for directed advertising");
      return kInvalidId;
    }
  }
  AdvertiserId id = pimpl_->allocate_advertiser();
  if (id == kInvalidId) {
    return id;
  }
  GetHandler()->Post(common::BindOnce(&impl::create_advertiser, common::Unretained(pimpl_.get()), id, config,
                                      scan_callback, set_terminated_callback, handler));
  return id;
}

AdvertiserId LeAdvertisingManager::ExtendedCreateAdvertiser(
    int reg_id,
    const ExtendedAdvertisingConfig config,
    const common::Callback<void(Address, AddressType)>& scan_callback,
    const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
    uint16_t duration,
    uint8_t max_extended_advertising_events,
    os::Handler* handler) {
  AdvertisingApiType advertising_api_type = pimpl_->get_advertising_api_type();
  if (advertising_api_type != AdvertisingApiType::EXTENDED) {
    return create_advertiser(config, scan_callback, set_terminated_callback, handler);
  };

  if (config.directed) {
    if (config.peer_address == Address::kEmpty) {
      LOG_INFO("Peer address can not be empty for directed advertising");
      return kInvalidId;
    }
  }
  if (config.channel_map == 0) {
    LOG_INFO("At least one channel must be set in the map");
    return kInvalidId;
  }
  if (!config.legacy_pdus) {
    if (config.connectable && config.scannable) {
      LOG_INFO("Extended advertising PDUs can not be connectable and scannable");
      return kInvalidId;
    }
    if (config.high_duty_directed_connectable) {
      LOG_INFO("Extended advertising PDUs can not be high duty cycle");
      return kInvalidId;
    }
  }
  if (config.interval_min > config.interval_max) {
    LOG_INFO("Advertising interval: min (%hu) > max (%hu)", config.interval_min, config.interval_max);
    return kInvalidId;
  }
  AdvertiserId id = pimpl_->allocate_advertiser();
  if (id == kInvalidId) {
    return id;
  }
  CallOn(
      pimpl_.get(),
      &impl::create_extended_advertiser,
      reg_id,
      id,
      config,
      scan_callback,
      set_terminated_callback,
      duration,
      max_extended_advertising_events,
      handler);
  return id;
}

void LeAdvertisingManager::SetParameters(AdvertiserId advertiser_id, ExtendedAdvertisingConfig config) {
  CallOn(pimpl_.get(), &impl::set_parameters, advertiser_id, config);
}

void LeAdvertisingManager::SetData(AdvertiserId advertiser_id, bool set_scan_rsp, std::vector<GapData> data) {
  CallOn(pimpl_.get(), &impl::set_data, advertiser_id, set_scan_rsp, data);
}

void LeAdvertisingManager::EnableAdvertiser(
    AdvertiserId advertiser_id, bool enable, uint16_t duration, uint8_t max_extended_advertising_events) {
  CallOn(pimpl_.get(), &impl::enable_advertiser, advertiser_id, enable, duration, max_extended_advertising_events);
}

void LeAdvertisingManager::SetPeriodicParameters(
    AdvertiserId advertiser_id, PeriodicAdvertisingParameters periodic_advertising_parameters) {
  CallOn(pimpl_.get(), &impl::set_periodic_parameter, advertiser_id, periodic_advertising_parameters);
}

void LeAdvertisingManager::SetPeriodicData(AdvertiserId advertiser_id, std::vector<GapData> data) {
  CallOn(pimpl_.get(), &impl::set_periodic_data, advertiser_id, data);
}

void LeAdvertisingManager::EnablePeriodicAdvertising(AdvertiserId advertiser_id, bool enable) {
  CallOn(pimpl_.get(), &impl::enable_periodic_advertising, advertiser_id, enable);
}

void LeAdvertisingManager::RemoveAdvertiser(AdvertiserId advertiser_id) {
  CallOn(pimpl_.get(), &impl::remove_advertiser, advertiser_id);
}

void LeAdvertisingManager::RegisterAdvertisingCallback(AdvertisingCallback* advertising_callback) {
  CallOn(pimpl_.get(), &impl::register_advertising_callback, advertising_callback);
}

void LeAdvertisingManager::RegisterSetTerminatedCallback(
    common::ContextualCallback<void(ErrorCode, uint16_t, hci::AddressWithType)> set_terminated_callback) {
  GetHandler()->CallOn(pimpl_.get(), &impl::register_set_terminated_callback, set_terminated_callback);
}

}  // namespace hci
}  // namespace bluetooth
