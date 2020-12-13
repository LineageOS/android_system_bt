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

#pragma once

#include "hci/controller.h"
#include "hci/hci_layer.h"
#include "hci/hci_packets.h"
#include "os/handler.h"

namespace bluetooth {
namespace iso {

namespace internal {

class IsoManagerImpl {
 public:
  explicit IsoManagerImpl(os::Handler* iso_handler, hci::HciLayer* hci_layer, hci::Controller* controller);

  void OnHciLeEvent(hci::LeMetaEventView event);

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
  void SetCigParametersComplete(hci::CommandCompleteView command_complete);
  void RemoveCig(uint8_t cig_id);
  void RemoveCigComplete(hci::CommandCompleteView command_complete);

 private:
  os::Handler* iso_handler_ __attribute__((unused));
  hci::LeIsoInterface* hci_le_iso_interface_;
  hci::Controller* controller_ __attribute__((unused));
};
}  // namespace internal
}  // namespace iso
}  // namespace bluetooth
