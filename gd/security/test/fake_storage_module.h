/*
 *
 *  Copyright 2019 The Android Open Source Project
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
 */

#include "storage/storage_module.h"

#include <filesystem>

namespace bluetooth {
namespace security {

static const std::chrono::milliseconds kTestConfigSaveDelay = std::chrono::milliseconds(100);

class FakeStorageModule : public storage::StorageModule {
 public:
  FakeStorageModule() : storage::StorageModule("/tmp/temp_config.txt", kTestConfigSaveDelay, 100, false, false) {}

  storage::ConfigCache* GetConfigCachePublic() {
    return StorageModule::GetConfigCache();
  }

  void SaveImmediatelyPublic() {
    StorageModule::SaveImmediately();
  }
};

}  // namespace security
}  // namespace bluetooth
