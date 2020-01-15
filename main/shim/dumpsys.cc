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

#define LOG_TAG "bt_shim_storage"

#include <base/logging.h>
#include <algorithm>
#include <list>

#include "main/shim/dumpsys.h"
#include "main/shim/entry.h"
#include "main/shim/shim.h"

using ::bluetooth::shim::GetDumpsys;

std::list<bluetooth::legacy::shim::Dumpsys*> dumpsys_manager_;

bluetooth::legacy::shim::Dumpsys::Dumpsys() {
  CHECK(std::find(dumpsys_manager_.begin(), dumpsys_manager_.end(), this) ==
        dumpsys_manager_.end());
  dumpsys_manager_.push_back(this);
}

bluetooth::legacy::shim::Dumpsys::~Dumpsys() {
  CHECK(std::find(dumpsys_manager_.begin(), dumpsys_manager_.end(), this) !=
        dumpsys_manager_.end());
  dumpsys_manager_.remove(this);
}

void bluetooth::shim::Dump(int fd) {
  for (auto& dumpsys : dumpsys_manager_) {
    dumpsys->Dump(fd);
  }
  if (bluetooth::shim::is_gd_stack_started_up()) {
    GetDumpsys()->Dump(fd);
  } else {
    dprintf(fd, "%s gd stack has not started up\n",
            "gd::shim::legacy::dumpsys");
  }
}
