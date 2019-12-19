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

#include <base/callback.h>
#include <base/location.h>
#include <string>
#include "common/message_loop_thread.h"

namespace bluetooth {
namespace shim {
namespace stub {

extern bool message_loop_thread_is_running_;
extern bool message_loop_thread_do_in_thread_;

}  // namespace stub
}  // namespace shim
}  // namespace bluetooth
