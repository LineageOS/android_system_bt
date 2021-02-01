/*
 * Copyright 2020 The Android Open Source Project
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

#include "hci/facade/le_initiator_address_facade.h"

#include <condition_variable>
#include <memory>
#include <mutex>

#include "common/bind.h"
#include "grpc/grpc_event_queue.h"
#include "hci/acl_manager.h"
#include "hci/facade/le_initiator_address_facade.grpc.pb.h"
#include "hci/facade/le_initiator_address_facade.pb.h"
#include "hci/hci_packets.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::packet::RawBuilder;

namespace bluetooth {
namespace hci {
namespace facade {

class LeInitiatorAddressFacadeService : public LeInitiatorAddressFacade::Service {
 public:
  LeInitiatorAddressFacadeService(AclManager* acl_manager, ::bluetooth::os::Handler* facade_handler)
      : acl_manager_(acl_manager),
        address_manager_(acl_manager_->GetLeAddressManager()),
        facade_handler_(facade_handler) {
    ASSERT(facade_handler_ != nullptr);
  }

  ::grpc::Status SetPrivacyPolicyForInitiatorAddress(
      ::grpc::ServerContext* context, const PrivacyPolicy* request, ::google::protobuf::Empty* writer) override {
    Address address = Address::kEmpty;
    LeAddressManager::AddressPolicy address_policy =
        static_cast<LeAddressManager::AddressPolicy>(request->address_policy());
    if (address_policy == LeAddressManager::AddressPolicy::USE_STATIC_ADDRESS) {
      ASSERT(Address::FromString(request->address_with_type().address().address(), address));
    }
    AddressWithType address_with_type(address, static_cast<AddressType>(request->address_with_type().type()));
    crypto_toolbox::Octet16 irk = {};
    auto request_irk_length = request->rotation_irk().end() - request->rotation_irk().begin();
    if (request_irk_length == crypto_toolbox::OCTET16_LEN) {
      std::vector<uint8_t> irk_data(request->rotation_irk().begin(), request->rotation_irk().end());
      std::copy_n(irk_data.begin(), crypto_toolbox::OCTET16_LEN, irk.begin());
    } else {
      ASSERT(request_irk_length == 0);
    }
    auto minimum_rotation_time = std::chrono::milliseconds(request->minimum_rotation_time());
    auto maximum_rotation_time = std::chrono::milliseconds(request->maximum_rotation_time());
    acl_manager_->SetPrivacyPolicyForInitiatorAddress(
        address_policy, address_with_type, minimum_rotation_time, maximum_rotation_time);
    return ::grpc::Status::OK;
  }

  ::grpc::Status GetCurrentInitiatorAddress(
      ::grpc::ServerContext* context,
      const ::google::protobuf::Empty* request,
      ::bluetooth::facade::BluetoothAddressWithType* response) override {
    AddressWithType current = address_manager_->GetCurrentAddress();
    auto bluetooth_address = new ::bluetooth::facade::BluetoothAddress();
    bluetooth_address->set_address(current.GetAddress().ToString());
    response->set_type(static_cast<::bluetooth::facade::BluetoothAddressTypeEnum>(current.GetAddressType()));
    response->set_allocated_address(bluetooth_address);
    return ::grpc::Status::OK;
  }

  ::grpc::Status GetAnotherAddress(
      ::grpc::ServerContext* context,
      const ::google::protobuf::Empty* request,
      ::bluetooth::facade::BluetoothAddressWithType* response) override {
    AddressWithType another = address_manager_->GetAnotherAddress();
    auto bluetooth_address = new ::bluetooth::facade::BluetoothAddress();
    bluetooth_address->set_address(another.GetAddress().ToString());
    response->set_type(static_cast<::bluetooth::facade::BluetoothAddressTypeEnum>(another.GetAddressType()));
    response->set_allocated_address(bluetooth_address);
    return ::grpc::Status::OK;
  }

 private:
  AclManager* acl_manager_;
  LeAddressManager* address_manager_;
  ::bluetooth::os::Handler* facade_handler_;
};

void LeInitiatorAddressFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<AclManager>();
}

void LeInitiatorAddressFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new LeInitiatorAddressFacadeService(GetDependency<AclManager>(), GetHandler());
}

void LeInitiatorAddressFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* LeInitiatorAddressFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory LeInitiatorAddressFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new LeInitiatorAddressFacadeModule(); });

}  // namespace facade
}  // namespace hci
}  // namespace bluetooth
