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
#include "osi/include/buffer.h"

#define MAX_BUFFER_SIZE 4096
#define MAX_NUM_SLICES 100

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  // Init our wrapper
  FuzzedDataProvider dataProvider(Data, Size);

  // Create our buffer
  size_t buf_size =
      dataProvider.ConsumeIntegralInRange<size_t>(1, MAX_BUFFER_SIZE);
  buffer_t* buf = buffer_new(buf_size);

  // These functions require a non-null buffer, according to the header
  // The size also needs to be over 1 to make slices
  if (buf != nullptr && buf_size > 1) {
    std::vector<buffer_t*> slices;

    // Make a bunch of refs to various slices of the buffer
    size_t num_slices =
        dataProvider.ConsumeIntegralInRange<size_t>(0, MAX_NUM_SLICES);
    for (size_t i = 0; i < num_slices; i++) {
      // If slice_size is zero or GT buf_size, lib throws an exception
      size_t slice_size =
          dataProvider.ConsumeIntegralInRange<size_t>(1, buf_size - 1);
      if (slice_size > 0) {
        buffer_t* new_slice = nullptr;
        if (slice_size == buf_size) {
          new_slice = buffer_new_ref(buf);
        } else {
          new_slice = buffer_new_slice(buf, slice_size);
        }

        // Add the slice to our vector so we can free it later
        slices.push_back(new_slice);
      }
    }

    // Retrieve the buffer ptr
    buffer_ptr(buf);

    // Free the slices
    for (const auto& slice : slices) {
      buffer_free(slice);
    }
  }

  // Free the root buffer
  buffer_free(buf);

  return 0;
}
