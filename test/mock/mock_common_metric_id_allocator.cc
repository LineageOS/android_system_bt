/*
 * Copyright 2021 The Android Open Source Project
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

/*
 * Generated mock file from original source file
 *   Functions generated:11
 */

#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include <base/logging.h>
#include <functional>
#include <mutex>
#include <thread>
#include "common/metric_id_allocator.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

namespace {

const size_t paired_device_cache_capacity{10};
const std::string paired_device_cache_log_tag("Mock");
}  // namespace

namespace bluetooth {
namespace common {

const int MetricIdAllocator::kMinId = 0;

MetricIdAllocator::MetricIdAllocator()
    : paired_device_cache_(paired_device_cache_capacity,
                           paired_device_cache_log_tag),
      temporary_device_cache_(paired_device_cache_capacity,
                              paired_device_cache_log_tag) {
  next_id_ = 0;
  initialized_ = true;
}

class MockMetricIdAllocator : public MetricIdAllocator {
 public:
  MockMetricIdAllocator() {}
};

MockMetricIdAllocator metric_id_allocator;

MetricIdAllocator& MetricIdAllocator::GetInstance() {
  mock_function_count_map[__func__]++;
  return metric_id_allocator;
}
MetricIdAllocator::~MetricIdAllocator() {}
bool MetricIdAllocator::Close() {
  mock_function_count_map[__func__]++;
  return false;
}
bool MetricIdAllocator::Init(
    const std::unordered_map<RawAddress, int>& paired_device_map,
    Callback save_id_callback, Callback forget_device_callback) {
  mock_function_count_map[__func__]++;
  return false;
}
bool MetricIdAllocator::IsEmpty() const {
  mock_function_count_map[__func__]++;
  return false;
}
bool MetricIdAllocator::IsValidId(const int id) {
  mock_function_count_map[__func__]++;
  return false;
}
bool MetricIdAllocator::SaveDevice(const RawAddress& mac_address) {
  mock_function_count_map[__func__]++;
  return false;
}
int MetricIdAllocator::AllocateId(const RawAddress& mac_address) {
  mock_function_count_map[__func__]++;
  return 0;
}
void MetricIdAllocator::ForgetDevice(const RawAddress& mac_address) {
  mock_function_count_map[__func__]++;
}
void MetricIdAllocator::ForgetDevicePostprocess(const RawAddress& mac_address,
                                                const int id) {
  mock_function_count_map[__func__]++;
}

}  // namespace common
}  // namespace bluetooth
