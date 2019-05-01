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

#pragma once

#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

#include "hal/hci_hal.h"

namespace bluetooth {
namespace hal {

class SnoopLogger {
 public:
  explicit SnoopLogger(const std::string& filename);

  enum class PacketType {
    CMD = 1,
    ACL = 2,
    SCO = 3,
    EVT = 4,
  };

  enum class Direction {
    INCOMING,
    OUTGOING,
  };

  void capture(const HciPacket& packet, Direction direction, PacketType type);

 private:
  bool file_exists_;
  std::ofstream btsnoop_ostream_;
  std::mutex file_mutex_;
};

}  // namespace hal
}  // namespace bluetooth
