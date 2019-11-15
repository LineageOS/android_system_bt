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
 * This common file provides the only visibility from the legacy stack into GD stack.
 *
 * Only interfaces or APIs should be exported.
 *
 * Only common data structures should be used to pass data between the stacks.
 *
 */
#include "gd/shim/iadvertising.h"
#include "gd/shim/iconnectability.h"
#include "gd/shim/icontroller.h"
#include "gd/shim/idiscoverability.h"
#include "gd/shim/ihci_layer.h"
#include "gd/shim/iinquiry.h"
#include "gd/shim/il2cap.h"
#include "gd/shim/iname.h"
#include "gd/shim/ipage.h"
#include "gd/shim/iscanning.h"
#include "gd/shim/istack.h"
