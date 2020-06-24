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

#include "os/parameter_provider.h"

#include <unistd.h>

#include <cerrno>

#include "os/log.h"

namespace bluetooth {
namespace os {

// Write to $PWD/bt_stack.conf if $PWD can be found, otherwise, write to $HOME/bt_stack.conf
std::string ParameterProvider::ConfigFilePath() {
  char cwd[PATH_MAX] = {};
  if (getcwd(cwd, sizeof(cwd)) == nullptr) {
    LOG_ERROR("Failed to get current working directory due to \"%s\", returning default", strerror(errno));
    return "bt_config.conf";
  }
  return std::string(cwd) + "/bt_config.conf";
}

}  // namespace os
}  // namespace bluetooth