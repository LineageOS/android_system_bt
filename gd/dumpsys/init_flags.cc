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

#include "common/init_flags.h"
#include "dumpsys/init_flags.h"
#include "init_flags_generated.h"

flatbuffers::Offset<bluetooth::common::InitFlagsData> bluetooth::dumpsys::InitFlags::Dump(
    flatbuffers::FlatBufferBuilder* fb_builder) {
  auto title = fb_builder->CreateString("----- Init Flags -----");
  common::InitFlagsDataBuilder builder(*fb_builder);
  builder.add_title(title);
  builder.add_gd_advertising_enabled(bluetooth::common::init_flags::gd_advertising_is_enabled());
  builder.add_gd_security_enabled(bluetooth::common::init_flags::gd_security_is_enabled());
  builder.add_gd_acl_enabled(bluetooth::common::init_flags::gd_acl_is_enabled());
  builder.add_gd_hci_enabled(bluetooth::common::init_flags::gd_hci_is_enabled());
  builder.add_gd_controller_enabled(bluetooth::common::init_flags::gd_controller_is_enabled());
  builder.add_gd_core_enabled(bluetooth::common::init_flags::gd_core_is_enabled());
  return builder.Finish();
}
