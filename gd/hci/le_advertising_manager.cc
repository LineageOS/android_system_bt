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

struct Advertiser {
  os::Handler* handler;
  common::Callback<void(Address, AddressType)> scan_callback;
  common::Callback<void(ErrorCode, uint8_t, uint8_t)> set_terminated_callback;
};

struct LeAdvertisingManager::impl {
  impl(Module* module, os::Handler* handler, hci::HciLayer* hci_layer, hci::Controller* controller)
      : registered_handler_(nullptr), module_(module), module_handler_(handler), hci_layer_(hci_layer),
        controller_(controller), le_advertising_interface_(nullptr), num_instances_(0) {}

  void start() {
    le_advertising_interface_ = hci_layer_->GetLeAdvertisingInterface(
        common::Bind(&LeAdvertisingManager::impl::handle_event, common::Unretained(this)), module_handler_);
    num_instances_ = controller_->GetControllerLeNumberOfSupportedAdverisingSets();
  }

  size_t GetNumberOfAdvertisingInstances() const {
    return num_instances_;
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
    registered_handler_->Post(common::BindOnce(set_terminated_callback_, event_view.GetStatus(),
                                               event_view.GetAdvertisingHandle(),
                                               event_view.GetNumCompletedExtendedAdvertisingEvents()));
  }

  AdvertiserId allocate_advertiser() {
    AdvertiserId id = 0;
    {
      std::unique_lock lock(id_mutex_);
      while (id < num_instances_ && advertising_sets_.count(id) == 0) {
        id++;
      }
    }
    if (id == num_instances_) {
      return kInvalidId;
    }
    return id;
  }

  void remove_advertiser(AdvertiserId id) {
    std::unique_lock lock(id_mutex_);
    if (advertising_sets_.count(id) == 0) {
      return;
    }
    advertising_sets_.erase(id);
  }

  void create_advertiser(AdvertiserId id, const AdvertisingConfig& config,
                         const common::Callback<void(Address, AddressType)>& scan_callback,
                         const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
                         os::Handler* handler) {
    advertising_sets_[id].scan_callback = scan_callback;
    advertising_sets_[id].set_terminated_callback = set_terminated_callback;
    advertising_sets_[id].handler = handler;
    if (!controller_->IsSupported(hci::OpCode::LE_MULTI_ADVT)) {
      le_advertising_interface_->EnqueueCommand(
          hci::LeSetAdvertisingParametersBuilder::Create(config.interval_min, config.interval_max, config.event_type,
                                                         config.address_type, config.peer_address_type,
                                                         config.peer_address, config.channel_map, config.filter_policy),
          common::BindOnce(impl::check_enable_status), module_handler_);
      le_advertising_interface_->EnqueueCommand(hci::LeSetAdvertisingDataBuilder::Create(config.advertisement),
                                                common::BindOnce(impl::check_enable_status), module_handler_);
      le_advertising_interface_->EnqueueCommand(hci::LeSetRandomAddressBuilder::Create(config.random_address),
                                                common::BindOnce(impl::check_enable_status), module_handler_);
      if (!config.scan_response.empty()) {
        le_advertising_interface_->EnqueueCommand(hci::LeSetScanResponseDataBuilder::Create(config.scan_response),
                                                  common::BindOnce(impl::check_enable_status), module_handler_);
      }
      le_advertising_interface_->EnqueueCommand(hci::LeSetAdvertisingDataBuilder::Create(config.advertisement),
                                                common::BindOnce(impl::check_enable_status), module_handler_);
      return;
    }
    le_advertising_interface_->EnqueueCommand(
        hci::LeMultiAdvtParamBuilder::Create(config.interval_min, config.interval_max, config.event_type,
                                             config.address_type, config.peer_address_type, config.peer_address,
                                             config.channel_map, config.filter_policy, id, config.tx_power),
        common::BindOnce(impl::check_enable_status), module_handler_);
    le_advertising_interface_->EnqueueCommand(hci::LeSetAdvertisingEnableBuilder::Create(Enable::ENABLED),
                                              common::BindOnce(impl::check_enable_status), module_handler_);
  }

  void create_extended_advertiser(AdvertiserId id, const ExtendedAdvertisingConfig& config,
                                  const common::Callback<void(Address, AddressType)>& scan_callback,
                                  const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback,
                                  os::Handler* handler) {
    if (!controller_->IsSupported(hci::OpCode::LE_SET_EXTENDED_ADVERTISING_PARAMETERS)) {
      create_advertiser(id, config, scan_callback, set_terminated_callback, handler);
      return;
    } else {
      LOG_ALWAYS_FATAL("LE_SET_EXTENDED_ADVERTISING_PARAMETERS isn't implemented.");
    }

    /*
    le_advertising_interface_->EnqueueCommand(hci::LeSetExtendedAdvertisingParametersBuilder::Create(config.interval_min,
    config.interval_max, config.event_type, config.address_type, config.peer_address_type, config.peer_address,
    config.channel_map, config.filter_policy, id, config.tx_power), common::BindOnce(impl::check_enable_status),
    module_handler_);
     */
    advertising_sets_[id].scan_callback = scan_callback;
    advertising_sets_[id].set_terminated_callback = set_terminated_callback;
    advertising_sets_[id].handler = handler;
  }

  void stop_advertising(AdvertiserId advertising_set) {
    if (advertising_sets_.find(advertising_set) == advertising_sets_.end()) {
      LOG_INFO("Unknown advertising set %u", advertising_set);
      return;
    }
    le_advertising_interface_->EnqueueCommand(hci::LeSetAdvertisingEnableBuilder::Create(Enable::DISABLED),
                                              common::BindOnce(impl::check_enable_status), module_handler_);
    std::unique_lock lock(id_mutex_);
    advertising_sets_.erase(advertising_set);
  }

  common::Callback<void(Address, AddressType)> scan_callback_;
  common::Callback<void(ErrorCode, uint8_t, uint8_t)> set_terminated_callback_;
  os::Handler* registered_handler_;
  Module* module_;
  os::Handler* module_handler_;
  hci::HciLayer* hci_layer_;
  hci::Controller* controller_;
  hci::LeAdvertisingInterface* le_advertising_interface_;
  std::map<AdvertiserId, Advertiser> advertising_sets_;

  std::mutex id_mutex_;
  size_t num_instances_;

  static void check_enable_status(CommandCompleteView view) {
    ASSERT(view.IsValid());
    auto status_view = LeSetAdvertisingEnableCompleteView::Create(view);
    ASSERT(status_view.IsValid());
    if (status_view.GetStatus() != ErrorCode::SUCCESS) {
      LOG_INFO("SetEnable returned status %s", ErrorCodeText(status_view.GetStatus()).c_str());
      return;
    }
  }
};

const AdvertiserId LeAdvertisingManager::kInvalidId = -1;

LeAdvertisingManager::LeAdvertisingManager() {
  pimpl_ = std::make_unique<impl>(this, GetHandler(), GetDependency<hci::HciLayer>(), GetDependency<hci::Controller>());
}

void LeAdvertisingManager::ListDependencies(ModuleList* list) {
  list->add<hci::HciLayer>();
  list->add<hci::Controller>();
}

void LeAdvertisingManager::Start() {
  pimpl_->start();
}

void LeAdvertisingManager::Stop() {
  pimpl_.reset();
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
      return kInvalidId;
    }
    if (config.event_type == hci::AdvertisingEventType::ADV_DIRECT_IND ||
        config.event_type == hci::AdvertisingEventType::ADV_DIRECT_IND_LOW) {
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

AdvertiserId LeAdvertisingManager::CreateAdvertiser(
    const ExtendedAdvertisingConfig& config, const common::Callback<void(Address, AddressType)>& scan_callback,
    const common::Callback<void(ErrorCode, uint8_t, uint8_t)>& set_terminated_callback, os::Handler* handler) {
  AdvertiserId id = pimpl_->allocate_advertiser();
  if (id == kInvalidId) {
    return id;
  }
  // Add error checking here
  GetHandler()->Post(common::BindOnce(&impl::create_extended_advertiser, common::Unretained(pimpl_.get()), id, config,
                                      scan_callback, set_terminated_callback, handler));
  return id;
}

void LeAdvertisingManager::RemoveAdvertiser(AdvertiserId id) {
  pimpl_->remove_advertiser(id);
}

}  // namespace hci
}  // namespace bluetooth