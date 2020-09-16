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
  LE_4_0 = 1,
  ANDROID_HCI = 2,
  LE_5_0 = 3,
};

struct Advertiser {
  os::Handler* handler;
  AddressWithType current_address;
  common::Callback<void(Address, AddressType)> scan_callback;
  common::Callback<void(ErrorCode, uint8_t, uint8_t)> set_terminated_callback;
  int8_t tx_power;
};

ExtendedAdvertisingConfig::ExtendedAdvertisingConfig(const AdvertisingConfig& config) : AdvertisingConfig(config) {
  switch (config.event_type) {
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
  if (config.address_type == AddressType::PUBLIC_DEVICE_ADDRESS) {
    own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
  } else if (config.address_type == AddressType::RANDOM_DEVICE_ADDRESS) {
    own_address_type = OwnAddressType::RANDOM_DEVICE_ADDRESS;
  }
  // TODO(b/149221472): Support fragmentation
  operation = Operation::COMPLETE_ADVERTISEMENT;
}

struct LeAdvertisingManager::impl : public bluetooth::hci::LeAddressManagerCallback {
  impl(Module* module) : module_(module), le_advertising_interface_(nullptr), num_instances_(0) {}

  ~impl() {
    if (address_manager_registered) {
      le_address_manager_->Unregister(this);
    }
  }

  void start(os::Handler* handler, hci::HciLayer* hci_layer, hci::Controller* controller,
             hci::AclManager* acl_manager) {
    module_handler_ = handler;
    hci_layer_ = hci_layer;
    controller_ = controller;
    le_address_manager_ = acl_manager->GetLeAddressManager();
    le_advertising_interface_ =
        hci_layer_->GetLeAdvertisingInterface(module_handler_->BindOn(this, &LeAdvertisingManager::impl::handle_event));
    num_instances_ = controller_->GetLeNumberOfSupportedAdverisingSets();
    enabled_sets_ = std::vector<EnabledSet>(num_instances_);
    for (size_t i = 0; i < enabled_sets_.size(); i++) {
      enabled_sets_[i].advertising_handle_ = kInvalidHandle;
    }

    if (controller_->IsSupported(hci::OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS)) {
      advertising_api_type_ = AdvertisingApiType::LE_5_0;
    } else if (controller_->IsSupported(hci::OpCode::LE_MULTI_ADVT)) {
      advertising_api_type_ = AdvertisingApiType::ANDROID_HCI;
    } else {
      advertising_api_type_ = AdvertisingApiType::LE_4_0;
    }
  }

  size_t GetNumberOfAdvertisingInstances() const {
    return num_instances_;
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

  void remove_advertiser(AdvertiserId id) {
    stop_advertising(id);
    std::unique_lock lock(id_mutex_);
    if (advertising_sets_.count(id) == 0) {
      return;
    }
    advertising_sets_.erase(id);
    if (advertising_sets_.empty() && address_manager_registered) {
      le_address_manager_->Unregister(this);
      address_manager_registered = false;
      paused = false;
    }
    if (advertising_api_type_ == AdvertisingApiType::LE_5_0) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeRemoveAdvertisingSetBuilder::Create(id),
          module_handler_->BindOnce(impl::check_status<LeRemoveAdvertisingSetCompleteView>));
    }
  }

  void create_advertiser(AdvertiserId id, const AdvertisingConfig& config,
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
      case (AdvertisingApiType::LE_4_0): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetAdvertisingParametersBuilder::Create(
                config.interval_min,
                config.interval_max,
                config.event_type,
                config.address_type,
                config.peer_address_type,
                config.peer_address,
                config.channel_map,
                config.filter_policy),
            module_handler_->BindOnce(impl::check_status<LeSetAdvertisingParametersCompleteView>));
        if (!config.scan_response.empty()) {
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetScanResponseDataBuilder::Create(config.scan_response),
              module_handler_->BindOnce(impl::check_status<LeSetScanResponseDataCompleteView>));
        }
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetAdvertisingDataBuilder::Create(config.advertisement),
            module_handler_->BindOnce(impl::check_status<LeSetAdvertisingDataCompleteView>));
        EnabledSet curr_set;
        curr_set.advertising_handle_ = id;
        enabled_sets_[id] = curr_set;
        if (!paused) {
          std::vector<EnabledSet> enabled_sets = {curr_set};
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetAdvertisingEnableBuilder::Create(Enable::ENABLED),
              module_handler_->BindOnceOn(
                  this,
                  &impl::on_set_advertising_enable_complete<LeSetAdvertisingEnableCompleteView>,
                  Enable::ENABLED,
                  enabled_sets));
        }
      } break;
      case (AdvertisingApiType::ANDROID_HCI): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtParamBuilder::Create(
                config.interval_min,
                config.interval_max,
                config.event_type,
                config.address_type,
                config.peer_address_type,
                config.peer_address,
                config.channel_map,
                config.filter_policy,
                id,
                config.tx_power),
            module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtSetDataBuilder::Create(config.advertisement, id),
            module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        if (!config.scan_response.empty()) {
          le_advertising_interface_->EnqueueCommand(
              hci::LeMultiAdvtSetScanRespBuilder::Create(config.scan_response, id),
              module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        }

        advertising_sets_[id].current_address = le_address_manager_->GetAnotherAddress();
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtSetRandomAddrBuilder::Create(advertising_sets_[id].current_address.GetAddress(), id),
            module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        if (!paused) {
          le_advertising_interface_->EnqueueCommand(
              hci::LeMultiAdvtSetEnableBuilder::Create(Enable::ENABLED, id),
              module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        }
        EnabledSet curr_set;
        curr_set.advertising_handle_ = id;
        enabled_sets_[id] = curr_set;
      } break;
      case (AdvertisingApiType::LE_5_0): {
        ExtendedAdvertisingConfig new_config = config;
        new_config.legacy_pdus = true;

        // sid must be in range 0x00 to 0x0F. Since no controller supports more than
        // 16 advertisers, it's safe to make sid equal to id.
        new_config.sid = id % 0x0F;

        create_extended_advertiser(id, new_config, scan_callback, set_terminated_callback, handler);
      } break;
    }
  }

  void create_extended_advertiser(AdvertiserId id, const ExtendedAdvertisingConfig& config,
                                  const common::Callback<void(Address, AddressType)>& scan_callback,
                                  const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
                                  os::Handler* handler) {
    if (advertising_api_type_ != AdvertisingApiType::LE_5_0) {
      create_advertiser(id, config, scan_callback, set_terminated_callback, handler);
      return;
    }

    advertising_sets_[id].scan_callback = scan_callback;
    advertising_sets_[id].set_terminated_callback = set_terminated_callback;
    advertising_sets_[id].handler = handler;

    if (!address_manager_registered) {
      le_address_manager_->Register(this);
      address_manager_registered = true;
    }

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
              id,
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
              &impl::on_set_extended_advertising_parameters_complete<LeSetExtendedAdvertisingParametersCompleteView>,
              id));
    } else {
      uint8_t legacy_properties = (config.connectable ? 0x1 : 0x00) | (config.scannable ? 0x2 : 0x00) |
                                  (config.directed ? 0x4 : 0x00) | (config.high_duty_directed_connectable ? 0x8 : 0x00);
      uint8_t extended_properties = (config.anonymous ? 0x20 : 0x00) | (config.include_tx_power ? 0x40 : 0x00);
      extended_properties = extended_properties >> 5;

      le_advertising_interface_->EnqueueCommand(
          hci::LeSetExtendedAdvertisingParametersBuilder::Create(
              id,
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
              &impl::on_set_extended_advertising_parameters_complete<LeSetExtendedAdvertisingParametersCompleteView>,
              id));
    }

    if (config.own_address_type == OwnAddressType::RANDOM_DEVICE_ADDRESS) {
      advertising_sets_[id].current_address = le_address_manager_->GetAnotherAddress();
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetExtendedAdvertisingRandomAddressBuilder::Create(
              id, advertising_sets_[id].current_address.GetAddress()),
          module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingRandomAddressCompleteView>));
    } else {
      advertising_sets_[id].current_address =
          AddressWithType(controller_->GetMacAddress(), AddressType::PUBLIC_DEVICE_ADDRESS);
    }
    if (!config.scan_response.empty()) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetExtendedAdvertisingScanResponseBuilder::Create(id, config.operation, config.fragment_preference,
                                                                   config.scan_response),
          module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingScanResponseCompleteView>));
    }
    le_advertising_interface_->EnqueueCommand(
        hci::LeSetExtendedAdvertisingDataBuilder::Create(id, config.operation, config.fragment_preference,
                                                         config.advertisement),
        module_handler_->BindOnce(impl::check_status<LeSetExtendedAdvertisingDataCompleteView>));

    EnabledSet curr_set;
    curr_set.advertising_handle_ = id;
    curr_set.duration_ = 0;                         // TODO: 0 means until the host disables it
    curr_set.max_extended_advertising_events_ = 0;  // TODO: 0 is no maximum
    std::vector<EnabledSet> enabled_sets = {curr_set};

    enabled_sets_[id] = curr_set;
    if (!paused) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::ENABLED, enabled_sets),
          module_handler_->BindOnceOn(
              this,
              &impl::on_set_extended_advertising_enable_complete<LeSetExtendedAdvertisingEnableCompleteView>,
              Enable::ENABLED,
              enabled_sets));
    }
  }

  void stop_advertising(AdvertiserId advertising_set) {
    if (advertising_sets_.find(advertising_set) == advertising_sets_.end()) {
      LOG_INFO("Unknown advertising set %u", advertising_set);
      return;
    }
    EnabledSet curr_set;
    curr_set.advertising_handle_ = advertising_set;
    std::vector<EnabledSet> enabled_vector{curr_set};

    switch (advertising_api_type_) {
      case (AdvertisingApiType::LE_4_0):
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetAdvertisingEnableBuilder::Create(Enable::DISABLED),
            module_handler_->BindOnceOn(
                this,
                &impl::on_set_advertising_enable_complete<LeSetAdvertisingEnableCompleteView>,
                Enable::DISABLED,
                enabled_vector));
        break;
      case (AdvertisingApiType::ANDROID_HCI):
        le_advertising_interface_->EnqueueCommand(
            hci::LeMultiAdvtSetEnableBuilder::Create(Enable::DISABLED, advertising_set),
            module_handler_->BindOnce(impl::check_status<LeMultiAdvtCompleteView>));
        break;
      case (AdvertisingApiType::LE_5_0): {
        le_advertising_interface_->EnqueueCommand(
            hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::DISABLED, enabled_vector),
            module_handler_->BindOnceOn(
                this,
                &impl::on_set_extended_advertising_enable_complete<LeSetExtendedAdvertisingEnableCompleteView>,
                Enable::DISABLED,
                enabled_vector));
      } break;
    }

    std::unique_lock lock(id_mutex_);
    enabled_sets_[advertising_set].advertising_handle_ = kInvalidHandle;
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
        case (AdvertisingApiType::LE_4_0): {
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetAdvertisingEnableBuilder::Create(Enable::DISABLED),
              module_handler_->BindOnceOn(
                  this,
                  &impl::on_set_advertising_enable_complete<LeSetAdvertisingEnableCompleteView>,
                  Enable::DISABLED,
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
        case (AdvertisingApiType::LE_5_0): {
          if (enabled_sets.size() != 0) {
            le_advertising_interface_->EnqueueCommand(
                hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::DISABLED, enabled_sets),
                module_handler_->BindOnceOn(
                    this,
                    &impl::on_set_extended_advertising_enable_complete<LeSetExtendedAdvertisingEnableCompleteView>,
                    Enable::DISABLED,
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
        case (AdvertisingApiType::LE_4_0): {
          le_advertising_interface_->EnqueueCommand(
              hci::LeSetAdvertisingEnableBuilder::Create(Enable::ENABLED),
              module_handler_->BindOnceOn(
                  this,
                  &impl::on_set_advertising_enable_complete<LeSetAdvertisingEnableCompleteView>,
                  Enable::ENABLED,
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
        case (AdvertisingApiType::LE_5_0): {
          if (enabled_sets.size() != 0) {
            le_advertising_interface_->EnqueueCommand(
                hci::LeSetExtendedAdvertisingEnableBuilder::Create(Enable::ENABLED, enabled_sets),
                module_handler_->BindOnceOn(
                    this,
                    &impl::on_set_extended_advertising_enable_complete<LeSetExtendedAdvertisingEnableCompleteView>,
                    Enable::ENABLED,
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
  hci::LeAdvertisingInterface* le_advertising_interface_;
  std::map<AdvertiserId, Advertiser> advertising_sets_;
  hci::LeAddressManager* le_address_manager_;
  bool address_manager_registered = false;
  bool paused = false;

  std::mutex id_mutex_;
  size_t num_instances_;
  std::vector<hci::EnabledSet> enabled_sets_;

  AdvertisingApiType advertising_api_type_{0};

  template <class View>
  void on_set_advertising_enable_complete(
      Enable enable, std::vector<EnabledSet> enabled_sets, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto complete_view = LeSetAdvertisingEnableCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    AdvertisingCallback::AdvertisingStatus advertising_status = AdvertisingCallback::AdvertisingStatus::SUCCESS;
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
    }

    if (advertising_callbacks_ == nullptr) {
      return;
    }
    for (EnabledSet enabled_set : enabled_sets) {
      uint8_t id = enabled_set.advertising_handle_;
      if (id == kInvalidHandle) {
        continue;
      }
      if (enable == Enable::ENABLED) {
        advertising_callbacks_->onAdvertisingEnabled(id, true, advertising_status);
      } else {
        advertising_callbacks_->onAdvertisingEnabled(id, false, advertising_status);
      }
    }
  }

  template <class View>
  void on_set_extended_advertising_enable_complete(
      Enable enable, std::vector<EnabledSet> enabled_sets, CommandCompleteView view) {
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
      uint8_t id = enabled_set.advertising_handle_;
      if (id == kInvalidHandle) {
        continue;
      }
      if (enable == Enable::ENABLED) {
        advertising_callbacks_->OnAdvertisingSetStarted(id, tx_power, advertising_status);
      } else {
        advertising_callbacks_->onAdvertisingEnabled(id, false, advertising_status);
      }
    }
  }

  template <class View>
  void on_set_extended_advertising_parameters_complete(AdvertiserId id, CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto complete_view = LeSetExtendedAdvertisingParametersCompleteView::Create(view);
    ASSERT(complete_view.IsValid());
    if (complete_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("Got a command complete with status %s", ErrorCodeText(complete_view.GetStatus()).c_str());
      return;
    }
    advertising_sets_[id].tx_power = complete_view.GetSelectedTxPower();
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

AdvertiserId LeAdvertisingManager::CreateAdvertiser(
    const AdvertisingConfig& config, const common::Callback<void(Address, AddressType)>& scan_callback,
    const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback, os::Handler* handler) {
  if (config.peer_address == Address::kEmpty) {
    if (config.address_type == hci::AddressType::PUBLIC_IDENTITY_ADDRESS ||
        config.address_type == hci::AddressType::RANDOM_IDENTITY_ADDRESS) {
      LOG_WARN("Peer address can not be empty");
      return kInvalidId;
    }
    if (config.event_type == hci::AdvertisingType::ADV_DIRECT_IND ||
        config.event_type == hci::AdvertisingType::ADV_DIRECT_IND_LOW) {
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
    const ExtendedAdvertisingConfig& config, const common::Callback<void(Address, AddressType)>& scan_callback,
    const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback, os::Handler* handler) {
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
  GetHandler()->Post(common::BindOnce(&impl::create_extended_advertiser, common::Unretained(pimpl_.get()), id, config,
                                      scan_callback, set_terminated_callback, handler));
  return id;
}

void LeAdvertisingManager::RemoveAdvertiser(AdvertiserId id) {
  GetHandler()->CallOn(pimpl_.get(), &impl::remove_advertiser, id);
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
