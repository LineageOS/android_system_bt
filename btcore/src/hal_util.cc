//
//  Copyright (C) 2015 Google, Inc.
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

#define LOG_TAG "hal_util"

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <hardware/bluetooth.h>
#include <hardware/hardware.h>

#include <dlfcn.h>
#include <errno.h>
#include <string.h>

#include "btcore/include/hal_util.h"
#include "osi/include/log.h"

using base::StringPrintf;

#define BLUETOOTH_LIBRARY_NAME "bluetooth.default.so"
#if defined(__LP64__)
#define BACKUP_PATH "/system/lib64/hw/" BLUETOOTH_LIBRARY_NAME
#else
#define BACKUP_PATH "/system/lib/hw/" BLUETOOTH_LIBRARY_NAME
#endif

int hal_util_load_bt_library(const struct hw_module_t** module) {
  const char* id = BT_STACK_MODULE_ID;
  const char* sym = HAL_MODULE_INFO_SYM_AS_STR;
  struct hw_module_t* hmi = nullptr;

  // Always try to load the default Bluetooth stack on GN builds.
  const char* path = BLUETOOTH_LIBRARY_NAME;
  void* handle = dlopen(path, RTLD_NOW);
  if (!handle) {
    const char* err_str = dlerror();
    LOG(WARNING) << __func__ << ": failed to load Bluetooth library " << path
                 << ", error=" << (err_str ? err_str : "error unknown");
    path = BACKUP_PATH;
    LOG(WARNING) << __func__ << ": loading backup path " << path;
    handle = dlopen(path, RTLD_NOW);
    if (!handle) {
      err_str = dlerror();
      LOG(ERROR) << __func__ << ": failed to load Bluetooth library " << path
                 << ", error=" << (err_str ? err_str : "error unknown");
      goto error;
    }
  }

  // Get the address of the struct hal_module_info.
  hmi = (struct hw_module_t*)dlsym(handle, sym);
  if (!hmi) {
    LOG(ERROR) << __func__ << ": failed to load symbol from Bluetooth library "
               << sym;
    goto error;
  }

  // Check that the id matches.
  if (strcmp(id, hmi->id) != 0) {
    LOG(ERROR) << StringPrintf("%s: id=%s does not match HAL module ID: %s",
                               __func__, id, hmi->id);
    goto error;
  }

  hmi->dso = handle;

  // Success.
  LOG(INFO) << StringPrintf("%s: loaded HAL id=%s path=%s hmi=%p handle=%p",
                            __func__, id, path, hmi, handle);

  *module = hmi;
  return 0;

error:
  *module = NULL;
  if (handle) dlclose(handle);

  return -EINVAL;
}
