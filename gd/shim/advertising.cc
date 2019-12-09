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
#define LOG_TAG "bt_gd_shim"

#include <functional>
#include <memory>

#include "hci/address.h"
#include "hci/hci_packets.h"
#include "hci/le_advertising_manager.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/advertising.h"

namespace bluetooth {
namespace shim {

struct Advertising::impl {
  impl(hci::LeAdvertisingManager* module, os::Handler* handler);
  ~impl();

  void StartAdvertising();
  void StopAdvertising();

  size_t GetNumberOfAdvertisingInstances() const;

 private:
  void OnScan(hci::Address address, hci::AddressType address_type);
  void OnTerminated(hci::ErrorCode code, uint8_t handle, uint8_t num_events);

  hci::AdvertiserId advertiser_id_{hci::LeAdvertisingManager::kInvalidId};

  hci::LeAdvertisingManager* advertising_manager_{nullptr};
  os::Handler* handler_;
};

const ModuleFactory Advertising::Factory = ModuleFactory([]() { return new Advertising(); });

Advertising::impl::impl(hci::LeAdvertisingManager* advertising_manager, os::Handler* handler)
    : advertising_manager_(advertising_manager), handler_(handler) {}

Advertising::impl::~impl() {}

void Advertising::impl::StartAdvertising() {
  if (advertiser_id_ == hci::LeAdvertisingManager::kInvalidId) {
    LOG_WARN("%s Already advertising; please stop prior to starting again", __func__);
    return;
  }

  hci::AdvertisingConfig config;
  advertiser_id_ =
      advertising_manager_->CreateAdvertiser(config, common::Bind(&impl::OnScan, common::Unretained(this)),
                                             common::Bind(&impl::OnTerminated, common::Unretained(this)), handler_);
  if (advertiser_id_ == hci::LeAdvertisingManager::kInvalidId) {
    LOG_WARN("%s Unable to start advertising", __func__);
    return;
  }
  LOG_DEBUG("%s Started advertising", __func__);
}

void Advertising::impl::StopAdvertising() {
  if (advertiser_id_ == hci::LeAdvertisingManager::kInvalidId) {
    LOG_WARN("%s No active advertising", __func__);
    return;
  }
  advertising_manager_->RemoveAdvertiser(advertiser_id_);
  advertiser_id_ = hci::LeAdvertisingManager::kInvalidId;
  LOG_DEBUG("%s Stopped advertising", __func__);
}

void Advertising::impl::OnScan(hci::Address address, hci::AddressType address_type) {
  LOG_INFO("%s UNIMPLEMENTED Received le advert from:%s", __func__, address.ToString().c_str());
}

void Advertising::impl::OnTerminated(hci::ErrorCode code, uint8_t handle, uint8_t num_events) {
  LOG_INFO("%s UNIMPLEMENTED", __func__);
}

size_t Advertising::impl::GetNumberOfAdvertisingInstances() const {
  return advertising_manager_->GetNumberOfAdvertisingInstances();
}

size_t Advertising::GetNumberOfAdvertisingInstances() const {
  return pimpl_->GetNumberOfAdvertisingInstances();
}

void Advertising::StartAdvertising() {
  pimpl_->StartAdvertising();
}

void Advertising::StopAdvertising() {
  pimpl_->StopAdvertising();
}

/**
 * Module methods
 */
void Advertising::ListDependencies(ModuleList* list) {
  list->add<hci::LeAdvertisingManager>();
}

void Advertising::Start() {
  pimpl_ = std::make_unique<impl>(GetDependency<hci::LeAdvertisingManager>(), GetHandler());
}

void Advertising::Stop() {
  pimpl_.reset();
}

}  // namespace shim
}  // namespace bluetooth
