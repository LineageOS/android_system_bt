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

#include "hci/device.h"

namespace bluetooth {
namespace security {
namespace record {

enum BondState { NOT_BONDED, PAIRING, BONDED };

class SecurityRecord {
 public:
  SecurityRecord(std::shared_ptr<hci::Device> device) : device_(device), state_(NOT_BONDED) {}

  /**
   * Returns true if the device is bonded to another device
   */
  bool IsBonded() {
    return state_ == BONDED;
  }

  /**
   * Returns true if a device is currently pairing to another device
   */
  bool IsPairing() {
    return state_ == PAIRING;
  }

  std::shared_ptr<hci::Device> GetDevice() {
    return device_;
  }

 private:
  const std::shared_ptr<hci::Device> device_;
  BondState state_;
};

}  // namespace record
}  // namespace security
}  // namespace bluetooth
