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

#define LOG_TAG "bt_shim_activity_attribution"
#include "activity_attribution.h"

#include "btif_common.h"
#include "gd/btaa/activity_attribution.h"
#include "helpers.h"
#include "main/shim/entry.h"

class ActivityAttributionInterfaceImpl
    : public ActivityAttributionInterface,
      public bluetooth::activity_attribution::ActivityAttributionCallback {
 public:
  ~ActivityAttributionInterfaceImpl() override = default;

  static ActivityAttributionInterfaceImpl* GetInstance() {
    static ActivityAttributionInterfaceImpl* instance =
        new ActivityAttributionInterfaceImpl();
    return instance;
  }

  void Init() override {
    bluetooth::shim::GetActivityAttribution()
        ->RegisterActivityAttributionCallback(this);
  }

  void RegisterCallbacks(ActivityAttributionCallbacks* callbacks) override {
    this->callbacks = callbacks;
  }

  void Cleanup(void) override{};

  void OnWakeup(const Activity activity,
                const bluetooth::hci::Address& address) override {
    do_in_jni_thread(
        FROM_HERE, base::Bind(&ActivityAttributionCallbacks::OnWakeup,
                              base::Unretained(callbacks),
                              (ActivityAttributionCallbacks::Activity)activity,
                              bluetooth::ToRawAddress(address)));
  }

 private:
  // Private constructor to prevent construction.
  ActivityAttributionInterfaceImpl() {}

  ActivityAttributionCallbacks* callbacks;
};

ActivityAttributionInterface*
bluetooth::shim::get_activity_attribution_instance() {
  return ActivityAttributionInterfaceImpl::GetInstance();
}
