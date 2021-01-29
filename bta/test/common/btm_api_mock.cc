/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
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

#include "btm_api_mock.h"

static bluetooth::manager::MockBtmInterface* btm_interface = nullptr;

void bluetooth::manager::SetMockBtmInterface(
    MockBtmInterface* mock_btm_interface) {
  btm_interface = mock_btm_interface;
}

bool BTM_GetSecurityFlagsByTransport(const RawAddress& bd_addr,
                                     uint8_t* p_sec_flags,
                                     tBT_TRANSPORT transport) {
  return btm_interface->GetSecurityFlagsByTransport(bd_addr, p_sec_flags,
                                                    transport);
}

tBTM_STATUS BTM_SetEncryption(const RawAddress& bd_addr,
                              tBT_TRANSPORT transport,
                              tBTM_SEC_CALLBACK* p_callback, void* p_ref_data,
                              tBTM_BLE_SEC_ACT sec_act) {
  return btm_interface->SetEncryption(bd_addr, transport, p_callback,
                                      p_ref_data, sec_act);
}
