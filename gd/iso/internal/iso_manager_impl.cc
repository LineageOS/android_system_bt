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
#include "iso_manager_impl.h"

#include "common/bind.h"
#include "iso/iso_manager.h"
#include "os/log.h"

namespace bluetooth {
namespace iso {
namespace internal {

IsoManagerImpl::IsoManagerImpl(os::Handler* iso_handler, hci::HciLayer* hci_layer, hci::Controller* controller)
    : iso_handler_(iso_handler),
      hci_le_iso_interface_(hci_layer->GetLeIsoInterface(iso_handler_->BindOn(this, &IsoManagerImpl::OnHciLeEvent))),
      controller_(controller) {}

void IsoManagerImpl::OnHciLeEvent(hci::LeMetaEventView event) {
  hci::SubeventCode code = event.GetSubeventCode();

  LOG_ERROR("Unhandled HCI LE ISO event, code %s", hci::SubeventCodeText(code).c_str());
}

void IsoManagerImpl::SetCigParameters(
    uint8_t cig_id,
    uint32_t sdu_interval_m_to_s,
    uint32_t sdu_interval_s_to_m,
    hci::ClockAccuracy peripherals_clock_accuracy,
    hci::Packing packing,
    hci::Enable framing,
    uint16_t max_transport_latency_m_to_s,
    uint16_t max_transport_latency_s_to_m,
    const std::vector<hci::CisParametersConfig>& cis_config) {
  hci_le_iso_interface_->EnqueueCommand(
      hci::LeSetCigParametersBuilder::Create(
          cig_id,
          sdu_interval_m_to_s,
          sdu_interval_s_to_m,
          peripherals_clock_accuracy,
          packing,
          framing,
          max_transport_latency_m_to_s,
          max_transport_latency_s_to_m,
          cis_config),
      iso_handler_->BindOnce(&IsoManagerImpl::SetCigParametersComplete, base::Unretained(this)));
}

void IsoManagerImpl::SetCigParametersComplete(hci::CommandCompleteView command_complete) {
  ASSERT(command_complete.IsValid());

  hci::LeSetCigParametersCompleteView setCigParamsComplete =
      hci::LeSetCigParametersCompleteView::Create(command_complete);
  ASSERT(setCigParamsComplete.IsValid());
}

void IsoManagerImpl::RemoveCig(uint8_t cig_id) {
  hci_le_iso_interface_->EnqueueCommand(
      hci::LeRemoveCigBuilder::Create(cig_id),
      iso_handler_->BindOnce(&IsoManagerImpl::RemoveCigComplete, base::Unretained(this)));
}

void IsoManagerImpl::RemoveCigComplete(hci::CommandCompleteView command_complete) {
  ASSERT(command_complete.IsValid());

  hci::LeRemoveCigCompleteView removeCigComplete = hci::LeRemoveCigCompleteView::Create(command_complete);
  ASSERT(removeCigComplete.IsValid());
}

}  // namespace internal
}  // namespace iso
}  // namespace bluetooth
