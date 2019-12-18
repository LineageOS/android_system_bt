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

#include <cstdint>
#include <map>

struct alarm_t;

namespace bluetooth {
namespace shim {
namespace stub {

bool alarm_is_set(char const* name);
uint64_t alarm_interval_ms(char const* name);
void* alarm_data(char const* name);

extern bool alarm_set_;
extern uint64_t alarm_set_interval_;
extern void* alarm_set_data_;

extern std::map<char const*, alarm_t*> name_to_alarm_map_;

}  // namespace stub
}  // namespace shim
}  // namespace bluetooth
