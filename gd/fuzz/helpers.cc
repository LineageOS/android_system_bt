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

#include "fuzz/helpers.h"
#include "common/bind.h"

namespace bluetooth {
namespace fuzz {

// cribbed from https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#magic-separator
std::vector<std::vector<uint8_t>> SplitInput(const uint8_t* data, size_t size, const uint8_t* separator,
                                             size_t separatorSize) {
  std::vector<std::vector<uint8_t>> result;
  assert(SeparatorSize > 0);
  auto beg = data;
  auto end = data + size;
  while (const uint8_t* pos = (const uint8_t*)memmem(beg, end - beg, separator, separatorSize)) {
    result.push_back({beg, pos});
    beg = pos + separatorSize;
  }
  if (beg < end) {
    result.push_back({beg, end});
  }
  return result;
}

void SentinelWorkItem::notify_handler_quiesced() {
  quiesce_promise_->set_value();
}

void SentinelWorkItem::WaitUntilFinishedOn(os::Handler* handler) {
  quiesce_promise_ = std::make_unique<std::promise<void>>();
  handler->Post(common::Bind(&SentinelWorkItem::notify_handler_quiesced, common::Unretained(this)));
  quiesce_promise_->get_future().wait_for(std::chrono::milliseconds(300));
  quiesce_promise_ = nullptr;
}

}  // namespace fuzz
}  // namespace bluetooth
