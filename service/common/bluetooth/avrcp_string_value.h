//
//  Copyright (C) 2017 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#pragma once

#include <utils/String16.h>

namespace bluetooth {

class AvrcpStringValue {
 public:
  AvrcpStringValue();
  AvrcpStringValue(const AvrcpStringValue& other);
  AvrcpStringValue(int id, const android::String16& value);
  ~AvrcpStringValue();

  int id() const { return id_; }
  const android::String16& value() const { return value_; }

 protected:
  int id_ = 0;
  android::String16 value_;
};

}  // namespace bluetooth
