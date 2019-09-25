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

#include <gmock/gmock.h>

#include "hci/address.h"
#include "hci/le_security_interface.h"
#include "smp/ui.h"

namespace bluetooth {
namespace smp {

class UIMock : public UI {
 public:
  UIMock() {}
  ~UIMock() override = default;

  MOCK_METHOD2(DisplayPairingPrompt, void(const bluetooth::hci::Address&, std::string&));
  MOCK_METHOD1(CancelPairingPrompt, void(const bluetooth::hci::Address&));
  MOCK_METHOD1(DisplayConfirmValue, void(uint32_t));
  MOCK_METHOD0(DisplayEnterPasskeyDialog, void());
  MOCK_METHOD1(DisplayPasskey, void(uint32_t));

 private:
  DISALLOW_COPY_AND_ASSIGN(UIMock);
};

class LeSecurityInterfaceMock : public hci::LeSecurityInterface {
 public:
  MOCK_METHOD3(EnqueueCommand,
               void(std::unique_ptr<hci::LeSecurityCommandBuilder> command,
                    common::OnceCallback<void(hci::CommandCompleteView)> on_complete, os::Handler* handler));
  MOCK_METHOD3(EnqueueCommand,
               void(std::unique_ptr<hci::LeSecurityCommandBuilder> command,
                    common::OnceCallback<void(hci::CommandStatusView)> on_status, os::Handler* handler));
};

}  // namespace smp
}  // namespace bluetooth