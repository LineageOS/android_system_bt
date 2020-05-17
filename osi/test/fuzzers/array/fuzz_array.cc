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

#include <fuzzer/FuzzedDataProvider.h>
#include "osi/include/array.h"

// Capping the element size at sizeof(uint32_t)+1
// because it looks like there's a buffer overread
#define MAX_ELEMENT_SIZE sizeof(uint32_t)
#define MAX_ARRAY_LEN 1024

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  // Init our wrapper
  FuzzedDataProvider dataProvider(Data, Size);

  // Attempt to init an array
  size_t element_size =
      dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_ELEMENT_SIZE);
  array_t* arr = array_new(element_size);

  // Functions can only be called on a non-null array_t, according to the .h
  if (arr != nullptr) {
    // How large do we want our array?
    size_t arr_len =
        dataProvider.ConsumeIntegralInRange<size_t>(0, MAX_ARRAY_LEN);
    if (arr_len > 0) {
      for (size_t i = 0; i < arr_len; i++) {
        uint32_t new_val = dataProvider.ConsumeIntegral<uint32_t>();
        // append_value() just derefs and calls append_ptr(),
        // so no need to fuzz separately
        array_append_value(arr, new_val);
      }

      // Pull the ptr to an element in the array
      size_t get_index =
          dataProvider.ConsumeIntegralInRange<size_t>(0, array_length(arr) - 1);
      array_at(arr, get_index);

      // Grab the array pointer
      array_ptr(arr);
    }
  }

  // Free the array (this can be performed on a nullptr)
  array_free(arr);

  return 0;
}
