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
#pragma once

#include <gmock/gmock.h>

#include "btm_api.h"

namespace bluetooth {
namespace manager {

class BtmInterface {
 public:
  virtual bool GetSecurityFlagsByTransport(const RawAddress& bd_addr,
                                           uint8_t* p_sec_flags,
                                           tBT_TRANSPORT transport) = 0;
  virtual tBTM_STATUS SetEncryption(const RawAddress& bd_addr,
                                    tBT_TRANSPORT transport,
                                    tBTM_SEC_CALLBACK* p_callback,
                                    void* p_ref_data,
                                    tBTM_BLE_SEC_ACT sec_act) = 0;
  virtual ~BtmInterface() = default;
};

class MockBtmInterface : public BtmInterface {
 public:
  MOCK_METHOD((bool), GetSecurityFlagsByTransport,
              (const RawAddress& bd_addr, uint8_t* p_sec_flags,
               tBT_TRANSPORT transport),
              (override));
  MOCK_METHOD((tBTM_STATUS), SetEncryption,
              (const RawAddress& bd_addr, tBT_TRANSPORT transport,
               tBTM_SEC_CALLBACK* p_callback, void* p_ref_data,
               tBTM_BLE_SEC_ACT sec_act),
              (override));
};

/**
 * Set the {@link MockBtmInterface} for testing
 *
 * @param mock_btm_interface pointer to mock btm interface, could be null
 */
void SetMockBtmInterface(MockBtmInterface* mock_btm_interface);

}  // namespace manager
}  // namespace bluetooth
