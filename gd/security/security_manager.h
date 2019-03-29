/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <memory>
#include <vector>

#include "hci/device.h"
#include "hci/device_database.h"
#include "security/internal/security_manager_impl.h"

namespace bluetooth {
namespace security {

/**
 * Manages the security attributes, pairing, bonding of devices, and the
 * encryption/decryption of communications.
 */
class SecurityManager {
 public:
  friend class SecurityModule;

  /**
   * Initialize the security record map from an internal device database.
   */
  void Init();

  /**
   * Checks the device for existing bond, if not bonded, initiates pairing.
   *
   * @param device pointer to device we want to bond with
   */
  void CreateBond(std::shared_ptr<hci::ClassicDevice> device);

  /**
   * Cancels the pairing process for this device.
   *
   * @param device pointer to device with which we want to cancel our bond
   */
  void CancelBond(std::shared_ptr<bluetooth::hci::ClassicDevice> device);

  /**
   * Disassociates the device and removes the persistent LTK
   *
   * @param device pointer to device we want to forget
   */
  void RemoveBond(std::shared_ptr<bluetooth::hci::ClassicDevice> device);

  /**
   * Register to listen for callback events from SecurityManager
   *
   * @param listener ISecurityManagerListener instance to handle callbacks
   */
  void RegisterCallbackListener(internal::ISecurityManagerListener* listener);

  /**
   * Unregister listener for callback events from SecurityManager
   *
   * @param listener ISecurityManagerListener instance to unregister
   */
  void UnregisterCallbackListener(internal::ISecurityManagerListener* listener);

 protected:
  SecurityManager(os::Handler* security_handler, internal::SecurityManagerImpl* security_manager_impl)
      : security_handler_(security_handler), security_manager_impl_(security_manager_impl) {}

 private:
  os::Handler* security_handler_ = nullptr;
  internal::SecurityManagerImpl* security_manager_impl_;
  DISALLOW_COPY_AND_ASSIGN(SecurityManager);
};

}  // namespace security
}  // namespace bluetooth
