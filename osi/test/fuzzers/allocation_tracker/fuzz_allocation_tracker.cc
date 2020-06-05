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
#include "osi/include/allocation_tracker.h"

#define MAX_NUM_FUNCTIONS 512
#define MAX_BUF_SIZE 256

// Add a tracker_initialized bool to track if we initialized or not
// (This is to handle a call to allocation_tracker_notify_alloc immediately
// returning the provided pointer if the allocator is not ready, and
// notify_free on the same ptr failing as the allocator did not
// track that allocation)
bool tracker_initialized = false;

struct alloc_struct {
  allocator_id_t alloc_id;
  void* ptr;
};

void freeAllocationVector(std::vector<alloc_struct>* alloc_vector) {
  // Free our allocated buffers
  for (const auto& alloc : *alloc_vector) {
    void* real_ptr = allocation_tracker_notify_free(alloc.alloc_id, alloc.ptr);
    if (real_ptr) {
      free(real_ptr);
    }
  }
  alloc_vector->clear();
}

void callArbitraryFunction(std::vector<alloc_struct>* alloc_vector,
                           FuzzedDataProvider* dataProvider) {
  // Get our function identifier
  switch (dataProvider->ConsumeIntegralInRange<char>(0, 6)) {
    // Let 0 be a NO-OP, as ConsumeIntegral will return 0 on an empty buffer
    // (This will likely bias whatever action is here to run more often)
    case 0:
      return;
    // Init
    case 1:
      allocation_tracker_init();
      tracker_initialized = true;
      return;
    case 2:
      // NOTE: This will print to stderr if allocations exist. May clutter logs
      allocation_tracker_expect_no_allocations();
      return;
    case 3: {
      alloc_struct alloc;
      // Determine allocator ID & buffer size (without canaries)
      alloc.alloc_id = dataProvider->ConsumeIntegral<allocator_id_t>();
      size_t size =
          dataProvider->ConsumeIntegralInRange<size_t>(1, MAX_BUF_SIZE);
      if (size == 0) {
        return;
      }
      // Get our size with canaries & allocate
      size_t real_size = allocation_tracker_resize_for_canary(size);
      void* tmp_ptr = malloc(real_size);
      if (tmp_ptr == nullptr) {
        return;
      }
      alloc.ptr =
          allocation_tracker_notify_alloc(alloc.alloc_id, tmp_ptr, size);
      // Put our id/ptr pair in our tracking vector to be freed later
      if (tracker_initialized && alloc.ptr) {
        alloc_vector->push_back(alloc);
      } else {
        free(tmp_ptr);
      }
    }
      return;
    case 4: {
      // Grab a ptr from our tracking vector & free it
      if (!alloc_vector->empty()) {
        size_t index = dataProvider->ConsumeIntegralInRange<size_t>(
            0, alloc_vector->size() - 1);
        alloc_struct alloc = alloc_vector->at(index);
        void* real_ptr =
            allocation_tracker_notify_free(alloc.alloc_id, alloc.ptr);
        if (real_ptr) {
          free(real_ptr);
        }
        alloc_vector->erase(alloc_vector->begin() + index);
      }
    }
      return;
    case 5: {
      size_t size =
          dataProvider->ConsumeIntegralInRange<size_t>(0, MAX_BUF_SIZE);
      allocation_tracker_resize_for_canary(size);
    }
      return;
    // Reset
    // NOTE: Should this be exempted from fuzzing? Header says to not call this,
    //       but it's still exposed. It also doesn't perform a full reset.
    case 6:
      // Have to actually free the mem first as reset doesn't do it
      freeAllocationVector(alloc_vector);
      allocation_tracker_reset();
      return;
    default:
      return;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  // Init our wrapper
  FuzzedDataProvider dataProvider(Data, Size);

  // Keep a vector of our allocated pointers
  std::vector<alloc_struct> alloc_vector;

  // How many functions are we going to call?
  size_t num_functions =
      dataProvider.ConsumeIntegralInRange<size_t>(0, MAX_NUM_FUNCTIONS);
  for (size_t i = 0; i < num_functions; i++) {
    callArbitraryFunction(&alloc_vector, &dataProvider);
  }

  // Free anything we've allocated over the course of the fuzzer loop
  freeAllocationVector(&alloc_vector);

  // Reset our tracker for the next run
  allocation_tracker_reset();
  return 0;
}
