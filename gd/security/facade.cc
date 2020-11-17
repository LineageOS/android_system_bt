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
#include "security/facade.h"

#include "grpc/grpc_event_queue.h"
#include "hci/address_with_type.h"
#include "hci/le_address_manager.h"
#include "l2cap/classic/security_policy.h"
#include "l2cap/le/l2cap_le_module.h"
#include "os/handler.h"
#include "security/facade.grpc.pb.h"
#include "security/security_manager_listener.h"
#include "security/security_module.h"
#include "security/ui.h"

using bluetooth::l2cap::le::L2capLeModule;

namespace bluetooth {
namespace security {

namespace {
constexpr uint8_t AUTH_REQ_NO_BOND = 0x01;
constexpr uint8_t AUTH_REQ_BOND = 0x01;
constexpr uint8_t AUTH_REQ_MITM_MASK = 0x04;
constexpr uint8_t AUTH_REQ_SECURE_CONNECTIONS_MASK = 0x08;
constexpr uint8_t AUTH_REQ_KEYPRESS_MASK = 0x10;
constexpr uint8_t AUTH_REQ_CT2_MASK = 0x20;
constexpr uint8_t AUTH_REQ_RFU_MASK = 0xC0;

facade::BluetoothAddressWithType ToFacadeAddressWithType(hci::AddressWithType address) {
  facade::BluetoothAddressWithType ret;

  ret.mutable_address()->set_address(address.GetAddress().ToString());
  ret.set_type(static_cast<facade::BluetoothAddressTypeEnum>(address.GetAddressType()));

  return ret;
}

}  // namespace

class SecurityModuleFacadeService : public SecurityModuleFacade::Service, public ISecurityManagerListener, public UI {
 public:
  SecurityModuleFacadeService(
      SecurityModule* security_module, L2capLeModule* l2cap_le_module, ::bluetooth::os::Handler* security_handler)
      : security_module_(security_module), l2cap_le_module_(l2cap_le_module), security_handler_(security_handler) {
    security_module_->GetSecurityManager()->RegisterCallbackListener(this, security_handler_);
    security_module_->GetSecurityManager()->SetUserInterfaceHandler(this, security_handler_);

    /* In order to receive connect/disconenct event, we must register service */
    l2cap_le_module_->GetFixedChannelManager()->RegisterService(
        bluetooth::l2cap::kLastFixedChannel - 2,
        common::BindOnce(&SecurityModuleFacadeService::OnL2capRegistrationCompleteLe, common::Unretained(this)),
        common::Bind(&SecurityModuleFacadeService::OnConnectionOpenLe, common::Unretained(this)),
        security_handler_);
  }

  void OnL2capRegistrationCompleteLe(
      l2cap::le::FixedChannelManager::RegistrationResult result,
      std::unique_ptr<l2cap::le::FixedChannelService> le_smp_service) {
    ASSERT_LOG(
        result == bluetooth::l2cap::le::FixedChannelManager::RegistrationResult::SUCCESS,
        "Failed to register to LE SMP Fixed Channel Service");
  }

  void OnConnectionOpenLe(std::unique_ptr<l2cap::le::FixedChannel> channel) {
    channel->RegisterOnCloseCallback(
        security_handler_,
        common::BindOnce(
            &SecurityModuleFacadeService::OnConnectionClosedLe, common::Unretained(this), channel->GetDevice()));
  }

  void OnConnectionClosedLe(hci::AddressWithType address, hci::ErrorCode error_code) {
    SecurityHelperMsg disconnected;
    *disconnected.mutable_peer() = ToFacadeAddressWithType(address);
    disconnected.set_message_type(HelperMsgType::DEVICE_DISCONNECTED);
    helper_events_.OnIncomingEvent(disconnected);
  }

  ::grpc::Status CreateBond(::grpc::ServerContext* context, const facade::BluetoothAddressWithType* request,
                            ::google::protobuf::Empty* response) override {
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address().address(), peer));
    hci::AddressType peer_type = hci::AddressType::PUBLIC_DEVICE_ADDRESS;
    security_module_->GetSecurityManager()->CreateBond(hci::AddressWithType(peer, peer_type));
    return ::grpc::Status::OK;
  }

  ::grpc::Status CreateBondLe(::grpc::ServerContext* context, const facade::BluetoothAddressWithType* request,
                              ::google::protobuf::Empty* response) override {
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address().address(), peer));
    hci::AddressType peer_type = static_cast<hci::AddressType>(request->type());
    security_module_->GetSecurityManager()->CreateBondLe(hci::AddressWithType(peer, peer_type));
    return ::grpc::Status::OK;
  }

  ::grpc::Status CancelBond(::grpc::ServerContext* context, const facade::BluetoothAddressWithType* request,
                            ::google::protobuf::Empty* response) override {
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address().address(), peer));
    hci::AddressType peer_type = hci::AddressType::PUBLIC_DEVICE_ADDRESS;
    security_module_->GetSecurityManager()->CancelBond(hci::AddressWithType(peer, peer_type));
    return ::grpc::Status::OK;
  }

  ::grpc::Status RemoveBond(::grpc::ServerContext* context, const facade::BluetoothAddressWithType* request,
                            ::google::protobuf::Empty* response) override {
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address().address(), peer));
    hci::AddressType peer_type = hci::AddressType::PUBLIC_DEVICE_ADDRESS;
    security_module_->GetSecurityManager()->RemoveBond(hci::AddressWithType(peer, peer_type));
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchUiEvents(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                               ::grpc::ServerWriter<UiMsg>* writer) override {
    return ui_events_.RunLoop(context, writer);
  }

  ::grpc::Status SendUiCallback(::grpc::ServerContext* context, const UiCallbackMsg* request,
                                ::google::protobuf::Empty* response) override {
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address().address().address(), peer));
    hci::AddressType remote_type = static_cast<hci::AddressType>(request->address().type());

    switch (request->message_type()) {
      case UiCallbackType::PASSKEY:
        security_module_->GetSecurityManager()->OnPasskeyEntry(
            hci::AddressWithType(peer, remote_type), request->numeric_value());
        break;
      case UiCallbackType::YES_NO:
        security_module_->GetSecurityManager()->OnConfirmYesNo(hci::AddressWithType(peer, remote_type),
                                                               request->boolean());
        break;
      case UiCallbackType::PAIRING_PROMPT:
        security_module_->GetSecurityManager()->OnPairingPromptAccepted(
            hci::AddressWithType(peer, remote_type), request->boolean());
        break;
      default:
        LOG_ERROR("Unknown UiCallbackType %d", static_cast<int>(request->message_type()));
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Unknown UiCallbackType");
    }
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchBondEvents(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                                 ::grpc::ServerWriter<BondMsg>* writer) override {
    return bond_events_.RunLoop(context, writer);
  }

  ::grpc::Status FetchHelperEvents(
      ::grpc::ServerContext* context,
      const ::google::protobuf::Empty* request,
      ::grpc::ServerWriter<SecurityHelperMsg>* writer) override {
    return helper_events_.RunLoop(context, writer);
  }
  ::grpc::Status SetIoCapability(::grpc::ServerContext* context, const IoCapabilityMessage* request,
                                 ::google::protobuf::Empty* response) override {
    security_module_->GetFacadeConfigurationApi()->SetIoCapability(
        static_cast<hci::IoCapability>(request->capability()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetLeIoCapability(
      ::grpc::ServerContext* context,
      const LeIoCapabilityMessage* request,
      ::google::protobuf::Empty* response) override {
    security_module_->GetFacadeConfigurationApi()->SetLeIoCapability(
        static_cast<security::IoCapability>(request->capabilities()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetAuthenticationRequirements(::grpc::ServerContext* context,
                                               const AuthenticationRequirementsMessage* request,
                                               ::google::protobuf::Empty* response) override {
    security_module_->GetFacadeConfigurationApi()->SetAuthenticationRequirements(
        static_cast<hci::AuthenticationRequirements>(request->requirement()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetLeAuthRequirements(
      ::grpc::ServerContext* context,
      const LeAuthRequirementsMessage* request,
      ::google::protobuf::Empty* response) override {
    uint8_t auth_req = request->bond() ? AUTH_REQ_BOND : AUTH_REQ_NO_BOND;

    if (request->mitm()) auth_req |= AUTH_REQ_MITM_MASK;
    if (request->secure_connections()) auth_req |= AUTH_REQ_SECURE_CONNECTIONS_MASK;
    if (request->keypress()) auth_req |= AUTH_REQ_KEYPRESS_MASK;
    if (request->ct2()) auth_req |= AUTH_REQ_CT2_MASK;
    if (request->reserved_bits()) auth_req |= (((request->reserved_bits()) << 6) & AUTH_REQ_RFU_MASK);

    security_module_->GetFacadeConfigurationApi()->SetLeAuthRequirements(auth_req);
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetLeMaximumEncryptionKeySize(
      ::grpc::ServerContext* context,
      const LeMaximumEncryptionKeySizeMessage* request,
      ::google::protobuf::Empty* response) override {
    security_module_->GetFacadeConfigurationApi()->SetLeMaximumEncryptionKeySize(
        request->maximum_encryption_key_size());
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetLeOobDataPresent(
      ::grpc::ServerContext* context,
      const LeOobDataPresentMessage* request,
      ::google::protobuf::Empty* response) override {
    security_module_->GetFacadeConfigurationApi()->SetLeOobDataPresent(
        static_cast<OobDataFlag>(request->data_present()));
    return ::grpc::Status::OK;
  }

  ::grpc::Status SetLeInitiatorAddressPolicy(
      ::grpc::ServerContext* context, const hci::PrivacyPolicy* request, ::google::protobuf::Empty* response) override {
    Address address = Address::kEmpty;
    hci::LeAddressManager::AddressPolicy address_policy =
        static_cast<hci::LeAddressManager::AddressPolicy>(request->address_policy());
    if (address_policy == hci::LeAddressManager::AddressPolicy::USE_STATIC_ADDRESS ||
        address_policy == hci::LeAddressManager::AddressPolicy::USE_PUBLIC_ADDRESS) {
      ASSERT(Address::FromString(request->address_with_type().address().address(), address));
    }
    hci::AddressWithType address_with_type(address, static_cast<hci::AddressType>(request->address_with_type().type()));
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
    security_module_->GetSecurityManager()->SetLeInitiatorAddressPolicyForTest(
        address_policy, address_with_type, irk, minimum_rotation_time, maximum_rotation_time);
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchEnforceSecurityPolicyEvents(
      ::grpc::ServerContext* context,
      const ::google::protobuf::Empty* request,
      ::grpc::ServerWriter<EnforceSecurityPolicyMsg>* writer) override {
    return enforce_security_policy_events_.RunLoop(context, writer);
  }

  ::grpc::Status EnforceSecurityPolicy(
      ::grpc::ServerContext* context,
      const SecurityPolicyMessage* request,
      ::google::protobuf::Empty* response) override {
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address().address().address(), peer));
    hci::AddressType peer_type = static_cast<hci::AddressType>(request->address().type());
    hci::AddressWithType peer_with_type(peer, peer_type);
    l2cap::classic::SecurityEnforcementInterface::ResultCallback callback =
        security_handler_->BindOnceOn(this, &SecurityModuleFacadeService::EnforceSecurityPolicyEvent);
    security_module_->GetFacadeConfigurationApi()->EnforceSecurityPolicy(
        peer_with_type, static_cast<l2cap::classic::SecurityPolicy>(request->policy()), std::move(callback));
    return ::grpc::Status::OK;
  }

  ::grpc::Status GetOutOfBandData(
      ::grpc::ServerContext* context,
      const ::google::protobuf::Empty* request,
      ::bluetooth::security::OobDataMessage* response) override {
    std::array<uint8_t, 16> le_sc_c;
    std::array<uint8_t, 16> le_sc_r;
    security_module_->GetFacadeConfigurationApi()->GetOutOfBandData(&le_sc_c, &le_sc_r);

    std::string le_sc_c_str(17, '\0');
    std::copy(le_sc_c.begin(), le_sc_c.end(), le_sc_c_str.data());
    response->set_le_sc_confirmation_value(le_sc_c_str);

    std::string le_sc_r_str(17, '\0');
    std::copy(le_sc_r.begin(), le_sc_r.end(), le_sc_r_str.data());
    response->set_le_sc_random_value(le_sc_r_str);

    return ::grpc::Status::OK;
  }

  ::grpc::Status SetOutOfBandData(
      ::grpc::ServerContext* context,
      const ::bluetooth::security::OobDataMessage* request,
      ::google::protobuf::Empty* response) override {
    hci::Address peer;
    ASSERT(hci::Address::FromString(request->address().address().address(), peer));
    hci::AddressType peer_type = static_cast<hci::AddressType>(request->address().type());
    hci::AddressWithType peer_with_type(peer, peer_type);

    // We can't simply iterate till end of string, because we have an empty byte added at the end. We know confirm and
    // random are fixed size, 16 bytes
    std::array<uint8_t, 16> le_sc_c;
    auto req_le_sc_c = request->le_sc_confirmation_value();
    std::copy(req_le_sc_c.begin(), req_le_sc_c.begin() + 16, le_sc_c.data());

    std::array<uint8_t, 16> le_sc_r;
    auto req_le_sc_r = request->le_sc_random_value();
    std::copy(req_le_sc_r.begin(), req_le_sc_r.begin() + 16, le_sc_r.data());

    security_module_->GetFacadeConfigurationApi()->SetOutOfBandData(peer_with_type, le_sc_c, le_sc_r);
    return ::grpc::Status::OK;
  }

  ::grpc::Status FetchDisconnectEvents(
      ::grpc::ServerContext* context,
      const ::google::protobuf::Empty* request,
      ::grpc::ServerWriter<DisconnectMsg>* writer) override {
    security_module_->GetFacadeConfigurationApi()->SetDisconnectCallback(
        common::Bind(&SecurityModuleFacadeService::DisconnectEventOccurred, common::Unretained(this)));
    return disconnect_events_.RunLoop(context, writer);
  }

  void DisconnectEventOccurred(bluetooth::hci::AddressWithType peer) {
    LOG_INFO("%s", peer.ToString().c_str());
    DisconnectMsg msg;
    *msg.mutable_address() = ToFacadeAddressWithType(peer);
    disconnect_events_.OnIncomingEvent(msg);
  }

  void DisplayPairingPrompt(const bluetooth::hci::AddressWithType& peer, std::string name) {
    LOG_INFO("%s", peer.ToString().c_str());
    UiMsg display_yes_no;
    *display_yes_no.mutable_peer() = ToFacadeAddressWithType(peer);
    display_yes_no.set_message_type(UiMsgType::DISPLAY_PAIRING_PROMPT);
    display_yes_no.set_unique_id(unique_id++);
    ui_events_.OnIncomingEvent(display_yes_no);
  }

  virtual void DisplayConfirmValue(ConfirmationData data) {
    const bluetooth::hci::AddressWithType& peer = data.GetAddressWithType();
    std::string name = data.GetName();
    uint32_t numeric_value = data.GetNumericValue();
    LOG_INFO("%s value = 0x%x", peer.ToString().c_str(), numeric_value);
    UiMsg display_with_value;
    *display_with_value.mutable_peer() = ToFacadeAddressWithType(peer);
    display_with_value.set_message_type(UiMsgType::DISPLAY_YES_NO_WITH_VALUE);
    display_with_value.set_numeric_value(numeric_value);
    display_with_value.set_unique_id(unique_id++);
    ui_events_.OnIncomingEvent(display_with_value);
  }

  void DisplayYesNoDialog(ConfirmationData data) override {
    const bluetooth::hci::AddressWithType& peer = data.GetAddressWithType();
    std::string name = data.GetName();
    LOG_INFO("%s", peer.ToString().c_str());
    UiMsg display_yes_no;
    *display_yes_no.mutable_peer() = ToFacadeAddressWithType(peer);
    display_yes_no.set_message_type(UiMsgType::DISPLAY_YES_NO);
    display_yes_no.set_unique_id(unique_id++);
    ui_events_.OnIncomingEvent(display_yes_no);
  }

  void DisplayPasskey(ConfirmationData data) override {
    const bluetooth::hci::AddressWithType& peer = data.GetAddressWithType();
    std::string name = data.GetName();
    uint32_t passkey = data.GetNumericValue();
    LOG_INFO("%s value = 0x%x", peer.ToString().c_str(), passkey);
    UiMsg display_passkey;
    *display_passkey.mutable_peer() = ToFacadeAddressWithType(peer);
    display_passkey.set_message_type(UiMsgType::DISPLAY_PASSKEY);
    display_passkey.set_numeric_value(passkey);
    display_passkey.set_unique_id(unique_id++);
    ui_events_.OnIncomingEvent(display_passkey);
  }

  void DisplayEnterPasskeyDialog(ConfirmationData data) override {
    const bluetooth::hci::AddressWithType& peer = data.GetAddressWithType();
    std::string name = data.GetName();
    LOG_INFO("%s", peer.ToString().c_str());
    UiMsg display_passkey_input;
    *display_passkey_input.mutable_peer() = ToFacadeAddressWithType(peer);
    display_passkey_input.set_message_type(UiMsgType::DISPLAY_PASSKEY_ENTRY);
    display_passkey_input.set_unique_id(unique_id++);
    ui_events_.OnIncomingEvent(display_passkey_input);
  }

  void Cancel(const bluetooth::hci::AddressWithType& peer) override {
    LOG_INFO("%s", peer.ToString().c_str());
    UiMsg display_cancel;
    *display_cancel.mutable_peer() = ToFacadeAddressWithType(peer);
    display_cancel.set_message_type(UiMsgType::DISPLAY_CANCEL);
    display_cancel.set_unique_id(unique_id++);
    ui_events_.OnIncomingEvent(display_cancel);
  }

  void OnDeviceBonded(hci::AddressWithType peer) override {
    LOG_INFO("%s", peer.ToString().c_str());
    BondMsg bonded;
    *bonded.mutable_peer() = ToFacadeAddressWithType(peer);
    bonded.set_message_type(BondMsgType::DEVICE_BONDED);
    bond_events_.OnIncomingEvent(bonded);
  }

  void OnEncryptionStateChanged(hci::EncryptionChangeView encryption_change_view) override {}

  void OnDeviceUnbonded(hci::AddressWithType peer) override {
    LOG_INFO("%s", peer.ToString().c_str());
    BondMsg unbonded;
    *unbonded.mutable_peer() = ToFacadeAddressWithType(peer);
    unbonded.set_message_type(BondMsgType::DEVICE_UNBONDED);
    bond_events_.OnIncomingEvent(unbonded);
  }

  void OnDeviceBondFailed(hci::AddressWithType peer, PairingFailure status) override {
    LOG_INFO("%s", peer.ToString().c_str());
    BondMsg bond_failed;
    *bond_failed.mutable_peer() = ToFacadeAddressWithType(peer);
    bond_failed.set_message_type(BondMsgType::DEVICE_BOND_FAILED);
    bond_failed.set_reason(static_cast<uint8_t>(status.reason));
    bond_events_.OnIncomingEvent(bond_failed);
  }

  void EnforceSecurityPolicyEvent(bool result) {
    EnforceSecurityPolicyMsg msg;
    msg.set_result(result);
    enforce_security_policy_events_.OnIncomingEvent(msg);
  }

 private:
  SecurityModule* security_module_;
  L2capLeModule* l2cap_le_module_;
  ::bluetooth::os::Handler* security_handler_;
  ::bluetooth::grpc::GrpcEventQueue<UiMsg> ui_events_{"UI events"};
  ::bluetooth::grpc::GrpcEventQueue<BondMsg> bond_events_{"Bond events"};
  ::bluetooth::grpc::GrpcEventQueue<SecurityHelperMsg> helper_events_{"Events that don't fit any other category"};
  ::bluetooth::grpc::GrpcEventQueue<EnforceSecurityPolicyMsg> enforce_security_policy_events_{
      "Enforce Security Policy Events"};
  ::bluetooth::grpc::GrpcEventQueue<DisconnectMsg> disconnect_events_{"Disconnect events"};
  uint32_t unique_id{1};
  std::map<uint32_t, common::OnceCallback<void(bool)>> user_yes_no_callbacks_;
  std::map<uint32_t, common::OnceCallback<void(uint32_t)>> user_passkey_callbacks_;
};

void SecurityModuleFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<SecurityModule>();
  list->add<L2capLeModule>();
}

void SecurityModuleFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ =
      new SecurityModuleFacadeService(GetDependency<SecurityModule>(), GetDependency<L2capLeModule>(), GetHandler());
}

void SecurityModuleFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* SecurityModuleFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory SecurityModuleFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new SecurityModuleFacadeModule(); });

}  // namespace security
}  // namespace bluetooth
