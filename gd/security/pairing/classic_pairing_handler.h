/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License") override;
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

#include "pairing_handler.h"

#include "security/smp_packets.h"

using namespace bluetooth::security::pairing;

namespace bluetooth {
namespace security {
namespace pairing {

class ClassicPairingHandler : public PairingHandler {
 public:
  explicit ClassicPairingHandler(std::shared_ptr<record::SecurityRecord> record) : PairingHandler(record) {}

  void Init() {
    // Set auth required
    // Connect to device
  }
};

}  // namespace pairing
}  // namespace security
}  // namespace bluetooth
