/******************************************************************************
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
 ******************************************************************************/

/* Activity Attribution Interface */

#include <hardware/bt_activity_attribution.h>

#include "btaa/include/activity_attribution.h"
#include "btif/include/btif_common.h"
#include "gd/common/init_flags.h"
#include "stack/include/btu.h"

using base::Bind;
using base::Unretained;

namespace bluetooth {
namespace activity_attribution {

std::unique_ptr<ActivityAttributionInterface> activityAttributionInstance;

class ActivityAttributionInterfaceImpl : public ActivityAttributionCallbacks,
                                         public ActivityAttributionInterface {
  ~ActivityAttributionInterfaceImpl() override = default;

  void Init(ActivityAttributionCallbacks* callbacks) override {
    if (!bluetooth::common::InitFlags::BtaaHciLogEnabled()) {
      LOG(INFO) << __func__ << " BTAA not enabled!";
      return;
    }

    this->callbacks = callbacks;
    ActivityAttribution::Initialize(this);
  }

  void OnWakeup(Activity activity, const RawAddress& address) override {
    VLOG(2) << __func__ << " activity: " << (int)activity
            << " address: " << address;
    do_in_jni_thread(FROM_HERE, Bind(&ActivityAttributionCallbacks::OnWakeup,
                                     Unretained(callbacks), activity, address));
  }

  void Cleanup(void) override {
    do_in_main_thread(FROM_HERE, Bind(&ActivityAttribution::CleanUp));
  }

 private:
  ActivityAttributionCallbacks* callbacks;
};

ActivityAttributionInterface* getActivityAttributionInterface() {
  if (!activityAttributionInstance)
    activityAttributionInstance.reset(new ActivityAttributionInterfaceImpl());

  return activityAttributionInstance.get();
}

}  // namespace activity_attribution
}  // namespace bluetooth
