/******************************************************************************
 *
 *  Copyright 2018 The Android Open Source Project
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
 ******************************************************************************/

#pragma once

#include <set>

#include "types/raw_address.h"

typedef uint8_t tGATT_IF;

namespace gatt {
namespace connection_manager {

/* for background connection */
extern bool background_connect_add(tGATT_IF gatt_if, const RawAddress& bd_addr);
extern bool background_connect_remove(tGATT_IF gatt_if,
                                      const RawAddress& bd_addr);
extern bool background_connect_remove_unconditional(const RawAddress& bd_addr);

extern void reset(bool after_reset);

extern void on_app_deregistered(tGATT_IF gatt_if);

extern std::set<tGATT_IF> get_apps_connecting_to(const RawAddress& remote_bda);

extern void dump(int fd);
}  // namespace connection_manager
}  // namespace gatt
