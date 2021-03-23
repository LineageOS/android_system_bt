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

#include "hci/acl_manager.h"

#include <atomic>
#include <future>
#include <set>

#include "common/bidi_queue.h"
#include "hci/acl_manager/classic_impl.h"
#include "hci/acl_manager/connection_management_callbacks.h"
#include "hci/acl_manager/le_acl_connection.h"
#include "hci/acl_manager/le_impl.h"
#include "hci/acl_manager/round_robin_scheduler.h"
#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci_acl_manager_generated.h"
#include "security/security_module.h"
#include "storage/storage_module.h"

namespace bluetooth {
namespace hci {

constexpr uint16_t kQualcommDebugHandle = 0xedc;

using acl_manager::AclConnection;
using common::Bind;
using common::BindOnce;

using acl_manager::classic_impl;
using acl_manager::ClassicAclConnection;
using acl_manager::ConnectionCallbacks;

using acl_manager::le_impl;
using acl_manager::LeAclConnection;
using acl_manager::LeConnectionCallbacks;

using acl_manager::RoundRobinScheduler;

struct AclManager::impl {
  impl(const AclManager& acl_manager) : acl_manager_(acl_manager) {}

  void Start() {
    hci_layer_ = acl_manager_.GetDependency<HciLayer>();
    handler_ = acl_manager_.GetHandler();
    controller_ = acl_manager_.GetDependency<Controller>();
    round_robin_scheduler_ = new RoundRobinScheduler(handler_, controller_, hci_layer_->GetAclQueueEnd());

    hci_queue_end_ = hci_layer_->GetAclQueueEnd();
    hci_queue_end_->RegisterDequeue(
        handler_, common::Bind(&impl::dequeue_and_route_acl_packet_to_connection, common::Unretained(this)));
    bool crash_on_unknown_handle = false;
    classic_impl_ =
        new classic_impl(hci_layer_, controller_, handler_, round_robin_scheduler_, crash_on_unknown_handle);
    le_impl_ = new le_impl(hci_layer_, controller_, handler_, round_robin_scheduler_, crash_on_unknown_handle);
  }

  void Stop() {
    delete le_impl_;
    delete classic_impl_;
    hci_queue_end_->UnregisterDequeue();
    delete round_robin_scheduler_;
    if (enqueue_registered_.exchange(false)) {
      hci_queue_end_->UnregisterEnqueue();
    }
    hci_queue_end_ = nullptr;
    handler_ = nullptr;
    hci_layer_ = nullptr;
  }

  // Invoked from some external Queue Reactable context 2
  void dequeue_and_route_acl_packet_to_connection() {
    auto packet = hci_queue_end_->TryDequeue();
    ASSERT(packet != nullptr);
    if (!packet->IsValid()) {
      LOG_INFO("Dropping invalid packet of size %zu", packet->size());
      return;
    }
    uint16_t handle = packet->GetHandle();
    if (handle == kQualcommDebugHandle) {
      return;
    }
    auto connection_pair = classic_impl_->acl_connections_.find(handle);
    if (connection_pair != classic_impl_->acl_connections_.end()) {
      connection_pair->second.assembler_.on_incoming_packet(*packet);
    } else {
      auto le_connection_pair = le_impl_->le_acl_connections_.find(handle);
      if (le_connection_pair == le_impl_->le_acl_connections_.end()) {
        LOG_INFO("Dropping packet of size %zu to unknown connection 0x%0hx", packet->size(), handle);
        return;
      }
      le_connection_pair->second.assembler_.on_incoming_packet(*packet);
    }
  }

  void Dump(
      std::promise<flatbuffers::Offset<AclManagerData>> promise, flatbuffers::FlatBufferBuilder* fb_builder) const;

  const AclManager& acl_manager_;

  classic_impl* classic_impl_ = nullptr;
  le_impl* le_impl_ = nullptr;
  os::Handler* handler_ = nullptr;
  Controller* controller_ = nullptr;
  HciLayer* hci_layer_ = nullptr;
  RoundRobinScheduler* round_robin_scheduler_ = nullptr;
  common::BidiQueueEnd<AclBuilder, AclView>* hci_queue_end_ = nullptr;
  std::atomic_bool enqueue_registered_ = false;
  uint16_t default_link_policy_settings_ = 0xffff;
};

AclManager::AclManager() : pimpl_(std::make_unique<impl>(*this)) {}

void AclManager::RegisterCallbacks(ConnectionCallbacks* callbacks, os::Handler* handler) {
  ASSERT(callbacks != nullptr && handler != nullptr);
  GetHandler()->Post(common::BindOnce(&classic_impl::handle_register_callbacks,
                                      common::Unretained(pimpl_->classic_impl_), common::Unretained(callbacks),
                                      common::Unretained(handler)));
}

void AclManager::UnregisterCallbacks(ConnectionCallbacks* callbacks, std::promise<void> promise) {
  ASSERT(callbacks != nullptr);
  CallOn(
      pimpl_->classic_impl_,
      &classic_impl::handle_unregister_callbacks,
      common::Unretained(callbacks),
      std::move(promise));
}

void AclManager::RegisterLeCallbacks(LeConnectionCallbacks* callbacks, os::Handler* handler) {
  ASSERT(callbacks != nullptr && handler != nullptr);
  CallOn(
      pimpl_->le_impl_,
      &le_impl::handle_register_le_callbacks,
      common::Unretained(callbacks),
      common::Unretained(handler));
}

void AclManager::UnregisterLeCallbacks(LeConnectionCallbacks* callbacks, std::promise<void> promise) {
  ASSERT(callbacks != nullptr);
  CallOn(pimpl_->le_impl_, &le_impl::handle_unregister_le_callbacks, common::Unretained(callbacks), std::move(promise));
}

void AclManager::CreateConnection(Address address) {
  CallOn(pimpl_->classic_impl_, &classic_impl::create_connection, address);
}

void AclManager::CreateLeConnection(AddressWithType address_with_type) {
  CallOn(pimpl_->le_impl_, &le_impl::create_le_connection, address_with_type, true);
}

void AclManager::SetLeSuggestedDefaultDataParameters(uint16_t octets, uint16_t time) {
  CallOn(pimpl_->le_impl_, &le_impl::set_le_suggested_default_data_parameters, octets, time);
}

void AclManager::SetPrivacyPolicyForInitiatorAddress(
    LeAddressManager::AddressPolicy address_policy,
    AddressWithType fixed_address,
    std::chrono::milliseconds minimum_rotation_time,
    std::chrono::milliseconds maximum_rotation_time) {
  crypto_toolbox::Octet16 rotation_irk{};
  auto irk = GetDependency<storage::StorageModule>()->GetAdapterConfig().GetLeIdentityResolvingKey();
  if (irk.has_value()) {
    rotation_irk = irk->bytes;
  }
  CallOn(
      pimpl_->le_impl_,
      &le_impl::set_privacy_policy_for_initiator_address,
      address_policy,
      fixed_address,
      rotation_irk,
      minimum_rotation_time,
      maximum_rotation_time);
}

// TODO(jpawlowski): remove once we have config file abstraction in cert tests
void AclManager::SetPrivacyPolicyForInitiatorAddressForTest(
    LeAddressManager::AddressPolicy address_policy,
    AddressWithType fixed_address,
    crypto_toolbox::Octet16 rotation_irk,
    std::chrono::milliseconds minimum_rotation_time,
    std::chrono::milliseconds maximum_rotation_time) {
  CallOn(
      pimpl_->le_impl_,
      &le_impl::set_privacy_policy_for_initiator_address_for_test,
      address_policy,
      fixed_address,
      rotation_irk,
      minimum_rotation_time,
      maximum_rotation_time);
}

void AclManager::CancelConnect(Address address) {
  CallOn(pimpl_->classic_impl_, &classic_impl::cancel_connect, address);
}

void AclManager::CancelLeConnect(AddressWithType address_with_type) {
  CallOn(pimpl_->le_impl_, &le_impl::cancel_connect, address_with_type);
}

void AclManager::AddDeviceToConnectList(AddressWithType address_with_type) {
  CallOn(pimpl_->le_impl_, &le_impl::add_device_to_connect_list, address_with_type);
}

void AclManager::AddDeviceToResolvingList(
    AddressWithType address_with_type,
    const std::array<uint8_t, 16>& peer_irk,
    const std::array<uint8_t, 16>& local_irk) {
  CallOn(pimpl_->le_impl_, &le_impl::add_device_to_resolving_list, address_with_type, peer_irk, local_irk);
}

void AclManager::RemoveDeviceFromConnectList(AddressWithType address_with_type) {
  CallOn(pimpl_->le_impl_, &le_impl::remove_device_from_connect_list, address_with_type);
}

void AclManager::RemoveDeviceFromResolvingList(AddressWithType address_with_type) {
  CallOn(pimpl_->le_impl_, &le_impl::remove_device_from_resolving_list, address_with_type);
}

void AclManager::CentralLinkKey(KeyFlag key_flag) {
  CallOn(pimpl_->classic_impl_, &classic_impl::central_link_key, key_flag);
}

void AclManager::SwitchRole(Address address, Role role) {
  CallOn(pimpl_->classic_impl_, &classic_impl::switch_role, address, role);
}

uint16_t AclManager::ReadDefaultLinkPolicySettings() {
  ASSERT_LOG(pimpl_->default_link_policy_settings_ != 0xffff, "Settings were never written");
  return pimpl_->default_link_policy_settings_;
}

void AclManager::WriteDefaultLinkPolicySettings(uint16_t default_link_policy_settings) {
  pimpl_->default_link_policy_settings_ = default_link_policy_settings;
  CallOn(pimpl_->classic_impl_, &classic_impl::write_default_link_policy_settings, default_link_policy_settings);
}

void AclManager::OnAdvertisingSetTerminated(ErrorCode status, uint16_t conn_handle, hci::AddressWithType adv_address) {
  if (status == ErrorCode::SUCCESS) {
    CallOn(pimpl_->le_impl_, &le_impl::UpdateLocalAddress, conn_handle, adv_address);
  }
}

void AclManager::SetSecurityModule(security::SecurityModule* security_module) {
  CallOn(pimpl_->classic_impl_, &classic_impl::set_security_module, security_module);
}

LeAddressManager* AclManager::GetLeAddressManager() {
  return pimpl_->le_impl_->le_address_manager_;
}

uint16_t AclManager::HACK_GetHandle(Address address) {
  return pimpl_->classic_impl_->HACK_get_handle(address);
}

uint16_t AclManager::HACK_GetLeHandle(Address address) {
  return pimpl_->le_impl_->HACK_get_handle(address);
}

void AclManager::HACK_SetScoDisconnectCallback(std::function<void(uint16_t, uint8_t)> callback) {
  pimpl_->classic_impl_->HACK_SetScoDisconnectCallback(callback);
}

void AclManager::HACK_SetAclTxPriority(uint8_t handle, bool high_priority) {
  CallOn(pimpl_->round_robin_scheduler_, &RoundRobinScheduler::SetLinkPriority, handle, high_priority);
}

void AclManager::ListDependencies(ModuleList* list) {
  list->add<HciLayer>();
  list->add<Controller>();
  list->add<storage::StorageModule>();
}

void AclManager::Start() {
  pimpl_->Start();
}

void AclManager::Stop() {
  pimpl_->Stop();
}

std::string AclManager::ToString() const {
  return "Acl Manager";
}

const ModuleFactory AclManager::Factory = ModuleFactory([]() { return new AclManager(); });

AclManager::~AclManager() = default;

void AclManager::impl::Dump(
    std::promise<flatbuffers::Offset<AclManagerData>> promise, flatbuffers::FlatBufferBuilder* fb_builder) const {
  auto title = fb_builder->CreateString("----- Acl Manager Dumpsys -----");
  AclManagerDataBuilder builder(*fb_builder);
  builder.add_title(title);
  flatbuffers::Offset<AclManagerData> dumpsys_data = builder.Finish();
  promise.set_value(dumpsys_data);
}

DumpsysDataFinisher AclManager::GetDumpsysData(flatbuffers::FlatBufferBuilder* fb_builder) const {
  ASSERT(fb_builder != nullptr);

  std::promise<flatbuffers::Offset<AclManagerData>> promise;
  auto future = promise.get_future();
  pimpl_->Dump(std::move(promise), fb_builder);

  auto dumpsys_data = future.get();

  return [dumpsys_data](DumpsysDataBuilder* dumpsys_builder) {
    dumpsys_builder->add_hci_acl_manager_dumpsys_data(dumpsys_data);
  };
}

}  // namespace hci
}  // namespace bluetooth
