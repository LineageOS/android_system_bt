/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#include "mock_gatt_layer.h"

static bluetooth::gatt::MockGattInterface* gatt_interface = nullptr;

void bluetooth::gatt::SetMockGattInterface(
    MockGattInterface* mock_gatt_interface) {
  gatt_interface = mock_gatt_interface;
}

bool gatt_profile_get_eatt_support(
    const RawAddress& peer_bda,
    base::OnceCallback<void(const RawAddress&, bool)> cb) {
  return gatt_interface->GetEattSupport(peer_bda, std::move(cb));
}
