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

#define LOG_TAG "bt_btif_activity_attribution"

#include "btif_activity_attribution.h"
#include "main/shim/activity_attribution.h"
#include "main/shim/shim.h"

using base::Bind;
using base::Unretained;

namespace bluetooth {
namespace activity_attribution {

ActivityAttributionInterface* get_activity_attribution_instance() {
  return bluetooth::shim::get_activity_attribution_instance();
}

}  // namespace activity_attribution
}  // namespace bluetooth
