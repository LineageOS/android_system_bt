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

#include <stdlib.h>

#include <map>

#include "btcore/include/module.h"
#include "main/shim/stub/osi.h"
#include "osi/include/alarm.h"

bool module_init(module_t const*) { return true; }
bool module_start_up(module_t const*) { return true; }
const module_t* get_module(const char*) { return nullptr; }
void module_clean_up(module_t const*) {}
void module_shut_down(module_t const*) {}

void* osi_alloc(size_t size) { return malloc(size); }
void* osi_calloc(size_t size) { return calloc(1, size); }

struct alarm_t {
  bool is_set_{false};
  uint64_t interval_ms_{0};
  void* data_{nullptr};
};

namespace bluetooth {
namespace shim {
namespace stub {

std::map<char const*, alarm_t*> name_to_alarm_map_;

}  // namespace stub
}  // namespace shim
}  // namespace bluetooth

// stub extensions
bool bluetooth::shim::stub::alarm_is_set(char const* name) {
  auto search = name_to_alarm_map_.find(name);
  CHECK(search != name_to_alarm_map_.end());
  alarm_t* alarm = search->second;
  CHECK(alarm != nullptr);
  return alarm->is_set_;
}

uint64_t bluetooth::shim::stub::alarm_interval_ms(char const* name) {
  auto search = name_to_alarm_map_.find(name);
  if (search == name_to_alarm_map_.end()) {
    return 0;
  }
  alarm_t* alarm = search->second;
  CHECK(alarm != nullptr);
  return alarm->interval_ms_;
}

void* bluetooth::shim::stub::alarm_data(char const* name) {
  auto search = name_to_alarm_map_.find(name);
  if (search == name_to_alarm_map_.end()) {
    return nullptr;
  }
  alarm_t* alarm = search->second;
  CHECK(alarm != nullptr);
  return alarm->data_;
}

alarm_t* alarm_new(char const* name) {
  if (bluetooth::shim::stub::name_to_alarm_map_.find(name) !=
      bluetooth::shim::stub::name_to_alarm_map_.end())
    CHECK(false) << "Duplicate alarm names";

  alarm_t* alarm = new struct alarm_t;
  bluetooth::shim::stub::name_to_alarm_map_[name] = alarm;
  return alarm;
}

void alarm_free(alarm_t* alarm) {
  char const* name = nullptr;
  for (auto& it : bluetooth::shim::stub::name_to_alarm_map_) {
    if (it.second == alarm) {
      name = it.first;
      break;
    }
  }
  if (name != nullptr) {
    bluetooth::shim::stub::name_to_alarm_map_.erase(name);
    delete alarm;
  }
}

void alarm_set_on_mloop(alarm_t* alarm, uint64_t interval_ms,
                        alarm_callback_t cb, void* data) {
  CHECK(alarm != nullptr);
  CHECK(alarm->is_set_ == false);
  alarm->is_set_ = true;
  alarm->interval_ms_ = interval_ms;
  alarm->data_ = data;
}

void alarm_cancel(alarm_t* alarm) {
  CHECK(alarm != nullptr);
  alarm->is_set_ = false;
  alarm->interval_ms_ = 0;
  alarm->data_ = nullptr;
}
