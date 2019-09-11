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

/**
 * Gabeldorsche related legacy-only-stack-side expansion and support code.
 */
#include "btcore/include/module.h"
#include "main/shim/entry.h"

static const char GD_SHIM_MODULE[] = "gd_shim_module";

namespace bluetooth {
namespace shim {

bool is_gd_shim_enabled();

}  // namespace shim
}  // namespace bluetooth
