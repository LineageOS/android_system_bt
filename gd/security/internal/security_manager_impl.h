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

#pragma once

#include "hci/classic_device.h"
#include "l2cap/classic/l2cap_classic_module.h"
#include "l2cap/le/l2cap_le_module.h"
#include "os/handler.h"
#include "security/channel/security_manager_channel.h"

namespace bluetooth {
namespace security {
namespace internal {

/**
 * Interface for listening to the channel for SMP commands.
 */
class ISecurityManagerListener {
 public:
  ISecurityManagerListener(os::Handler* handler) : handler_(handler) {}
  virtual ~ISecurityManagerListener() = default;

  /**
   * Called when a device is successfully bonded.
   *
   * @param device pointer to the bonded device
   */
  virtual void OnDeviceBonded(std::shared_ptr<bluetooth::hci::Device> device);

  /**
   * Called when a device is successfully un-bonded.
   *
   * @param device pointer to the device that is no longer bonded
   */
  virtual void OnDeviceUnbonded(std::shared_ptr<bluetooth::hci::Device> device);

  /**
   * Called as a result of a failure during the bonding process.
   *
   * @param device pointer to the device that is no longer bonded
   */
  virtual void OnDeviceBondFailed(std::shared_ptr<bluetooth::hci::Device> device);

  bool operator==(const ISecurityManagerListener& rhs) const {
    return &*this == &rhs;
  }

  os::Handler* handler_ = nullptr;
};

class SecurityManagerImpl /*: public channel::ISecurityManagerChannelListener*/ {
 public:
  explicit SecurityManagerImpl(os::Handler* security_handler, l2cap::le::L2capLeModule* l2cap_le_module,
                               l2cap::classic::L2capClassicModule* l2cap_classic_module,
                               channel::SecurityManagerChannel* security_manager_channel)
      : security_handler_(security_handler), l2cap_le_module_(l2cap_le_module),
        l2cap_classic_module_(l2cap_classic_module), security_manager_channel_(security_manager_channel) {}
  virtual ~SecurityManagerImpl() = default;

  // All APIs must be invoked in SM layer handler

  /**
   * Initialize the security record map from an internal device database.
   */
  void Init();

  /**
   * Checks the device for existing bond, if not bonded, initiates pairing.
   *
   * @param device pointer to device we want to bond with
   * @return true if bonded or pairing started successfully, false if currently pairing
   */
  void CreateBond(std::shared_ptr<hci::ClassicDevice> device);

  /* void CreateBond(std::shared_ptr<hci::LeDevice> device); */

  /**
   * Cancels the pairing process for this device.
   *
   * @param device pointer to device with which we want to cancel our bond
   * @return <code>true</code> if successfully stopped
   */
  void CancelBond(std::shared_ptr<bluetooth::hci::ClassicDevice> device);

  /* void CancelBond(std::shared_ptr<hci::LeDevice> device); */

  /**
   * Disassociates the device and removes the persistent LTK
   *
   * @param device pointer to device we want to forget
   * @return true if removed
   */
  void RemoveBond(std::shared_ptr<bluetooth::hci::ClassicDevice> device);

  /* void RemoveBond(std::shared_ptr<hci::LeDevice> device); */

  /**
   * Register to listen for callback events from SecurityManager
   *
   * @param listener ISecurityManagerListener instance to handle callbacks
   */
  void RegisterCallbackListener(ISecurityManagerListener* listener);

  /**
   * Unregister listener for callback events from SecurityManager
   *
   * @param listener ISecurityManagerListener instance to unregister
   */
  void UnregisterCallbackListener(ISecurityManagerListener* listener);

 protected:
  std::vector<ISecurityManagerListener*> listeners_;
  void FireDeviceBondedCallbacks(std::shared_ptr<bluetooth::hci::Device> device);
  void FireBondFailedCallbacks(std::shared_ptr<bluetooth::hci::Device> device);
  void FireUnbondCallbacks(std::shared_ptr<bluetooth::hci::Device> device);

  // ISecurityManagerChannel
  void OnChangeConnectionLinkKeyComplete(std::shared_ptr<hci::Device> device,
                                         hci::ChangeConnectionLinkKeyCompleteView packet);
  void OnMasterLinkKeyComplete(std::shared_ptr<hci::Device> device, hci::MasterLinkKeyCompleteView packet);
  void OnPinCodeRequest(std::shared_ptr<hci::Device> device, hci::PinCodeRequestView packet);
  void OnLinkKeyRequest(std::shared_ptr<hci::Device> device, hci::LinkKeyRequestView packet);
  void OnLinkKeyNotification(std::shared_ptr<hci::Device> device, hci::LinkKeyNotificationView packet);
  void OnIoCapabilityRequest(std::shared_ptr<hci::Device> device, hci::IoCapabilityRequestView packet);
  void OnIoCapabilityResponse(std::shared_ptr<hci::Device> device, hci::IoCapabilityResponseView packet);
  void OnSimplePairingComplete(std::shared_ptr<hci::Device> device, hci::SimplePairingCompleteView packet);
  void OnReturnLinkKeys(std::shared_ptr<hci::Device> device, hci::ReturnLinkKeysView packet);
  void OnEncryptionChange(std::shared_ptr<hci::Device> device, hci::EncryptionChangeView packet);
  void OnEncryptionKeyRefreshComplete(std::shared_ptr<hci::Device> device,
                                      hci::EncryptionKeyRefreshCompleteView packet);
  void OnRemoteOobDataRequest(std::shared_ptr<hci::Device> device, hci::RemoteOobDataRequestView packet);

 private:
  os::Handler* security_handler_ __attribute__((unused));
  l2cap::le::L2capLeModule* l2cap_le_module_ __attribute__((unused));
  l2cap::classic::L2capClassicModule* l2cap_classic_module_ __attribute__((unused));
  channel::SecurityManagerChannel* security_manager_channel_ __attribute__((unused));
};
}  // namespace internal
}  // namespace security
}  // namespace bluetooth
