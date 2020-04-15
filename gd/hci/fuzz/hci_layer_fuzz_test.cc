/*
 * Copyright 2019 The Android Open Source Project
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

#include <stddef.h>
#include <stdint.h>
#include "hal/fuzz/fuzz_hci_hal.h"
#include "hci/fuzz/dev_null_hci.h"
#include "hci/hci_layer.h"
#include "module.h"
#include "os/fuzz/fake_timerfd.h"
#include "os/log.h"

#include <fuzzer/FuzzedDataProvider.h>

using bluetooth::TestModuleRegistry;
using bluetooth::hal::HciHal;
using bluetooth::hal::fuzz::FuzzHciHal;
using bluetooth::hci::fuzz::DevNullHci;
using bluetooth::os::fuzz::fake_timerfd_advance;
using bluetooth::os::fuzz::fake_timerfd_reset;

static std::vector<uint8_t> GetArbitraryBytes(FuzzedDataProvider* fdp) {
  return fdp->ConsumeBytes<uint8_t>(fdp->ConsumeIntegral<size_t>());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider dataProvider(data, size);

  static TestModuleRegistry moduleRegistry = TestModuleRegistry();
  FuzzHciHal* fuzzHal = new FuzzHciHal();

  moduleRegistry.InjectTestModule(&HciHal::Factory, fuzzHal);
  moduleRegistry.Start<DevNullHci>(&moduleRegistry.GetTestThread());
  DevNullHci* devNullHci = moduleRegistry.GetModuleUnderTest<DevNullHci>();

  while (dataProvider.remaining_bytes() > 0) {
    const uint8_t action = dataProvider.ConsumeIntegralInRange(0, 12);
    switch (action) {
      case 1:
        fake_timerfd_advance(dataProvider.ConsumeIntegral<uint64_t>());
        break;
      case 2:
        fuzzHal->injectAclData(GetArbitraryBytes(&dataProvider));
        break;
      case 3:
        fuzzHal->injectHciEvent(GetArbitraryBytes(&dataProvider));
        break;
      case 4:
        fuzzHal->injectScoData(GetArbitraryBytes(&dataProvider));
        break;
      case 5:
        devNullHci->injectAclData(GetArbitraryBytes(&dataProvider));
        break;
      case 6:
        devNullHci->injectHciCommand(GetArbitraryBytes(&dataProvider));
        break;
      case 7:
        // TODO: devNullHci->injectSecurityCommand(GetArbitraryBytes(&dataProvider));
        break;
      case 8:
        devNullHci->injectLeSecurityCommand(GetArbitraryBytes(&dataProvider));
        break;
      case 9:
        devNullHci->injectAclConnectionCommand(GetArbitraryBytes(&dataProvider));
        break;
      case 10:
        devNullHci->injectLeAclConnectionCommand(GetArbitraryBytes(&dataProvider));
        break;
      case 11:
        devNullHci->injectLeAdvertisingCommand(GetArbitraryBytes(&dataProvider));
        break;
      case 12:
        devNullHci->injectLeScanningCommand(GetArbitraryBytes(&dataProvider));
        break;
    }
  }

  if (!moduleRegistry.GetTestThread().GetReactor()->WaitForIdle(std::chrono::milliseconds(100))) {
    LOG_ERROR("idle timed out");
  }
  moduleRegistry.StopAll();
  fake_timerfd_reset();
  return 0;
}
