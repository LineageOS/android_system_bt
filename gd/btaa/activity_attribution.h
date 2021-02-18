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

#include "hci/address.h"
#include "module.h"

namespace bluetooth {
namespace activity_attribution {

enum class Activity : uint8_t { UNKNOWN = 0, ADVERTISE, CONNECT, CONTROL, SCAN, HFP, VENDOR };

class ActivityAttributionCallback {
 public:
  virtual ~ActivityAttributionCallback() = default;

  // Callback when Blutooth woke up the system
  virtual void OnWakeup(const Activity activity, const hci::Address& address) = 0;
};

class ActivityAttribution : public bluetooth::Module {
 public:
  ActivityAttribution() = default;
  ~ActivityAttribution() = default;

  void RegisterActivityAttributionCallback(ActivityAttributionCallback* callback);

  static const ModuleFactory Factory;

 protected:
  std::string ToString() const override;
  void ListDependencies(ModuleList* list) override;
  void Start() override;
  void Stop() override;

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;

  DISALLOW_COPY_AND_ASSIGN(ActivityAttribution);
};

}  // namespace activity_attribution
}  // namespace bluetooth
