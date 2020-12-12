/*
 *
 *  Copyright 2020 The Android Open Source Project
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
 */

#pragma once

#include <memory>
#include <vector>

#include "hci/address_with_type.h"
#include "iso/internal/iso_manager_impl.h"

namespace bluetooth {
namespace iso {

/**
 * Manages the iso attributes, pairing, bonding of devices, and the
 * encryption/decryption of communications.
 */
class IsoManager {
 public:
  friend class IsoModule;

  void SetCigParameters(
      uint8_t cig_id,
      uint32_t sdu_interval_m_to_s,
      uint32_t sdu_interval_s_to_m,
      hci::ClockAccuracy peripherals_clock_accuracy,
      hci::Packing packing,
      hci::Enable framing,
      uint16_t max_transport_latency_m_to_s,
      uint16_t max_transport_latency_s_to_m,
      const std::vector<hci::CisParametersConfig>& cis_config);
  void RemoveCig(uint8_t cig_id);

 protected:
  IsoManager(os::Handler* iso_handler, internal::IsoManagerImpl* iso_manager_impl)
      : iso_handler_(iso_handler), iso_manager_impl_(iso_manager_impl) {}

 private:
  os::Handler* iso_handler_ = nullptr;
  internal::IsoManagerImpl* iso_manager_impl_;
  DISALLOW_COPY_AND_ASSIGN(IsoManager);
};

}  // namespace iso
}  // namespace bluetooth
