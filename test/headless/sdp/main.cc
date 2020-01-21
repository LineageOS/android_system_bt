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

#define LOG_TAG "bt_headless_sdp"

#include <future>

#include "base/logging.h"     // LOG() stdout and android log
#include "osi/include/log.h"  // android log only
#include "stack/include/sdp_api.h"
#include "test/headless/get_options.h"
#include "test/headless/headless.h"
#include "types/raw_address.h"

static void bta_jv_start_discovery_callback(uint16_t result, void* user_data) {
  auto promise = static_cast<std::promise<uint16_t>*>(user_data);
  promise->set_value(result);
}

constexpr size_t kMaxDiscoveryRecords = 16;

int sdp_query_uuid(int num_loops, const RawAddress& raw_address,
                   const bluetooth::Uuid& uuid) {
  for (int i = 0; i < num_loops; i++) {
    tSDP_DISCOVERY_DB* sdp_discovery_db = (tSDP_DISCOVERY_DB*)malloc(
        sizeof(tSDP_DISCOVERY_DB) +
        sizeof(tSDP_DISC_REC) * kMaxDiscoveryRecords);

    if (!SDP_InitDiscoveryDb(sdp_discovery_db,
                             sizeof(tSDP_DISCOVERY_DB) +
                                 sizeof(tSDP_DISC_REC) * kMaxDiscoveryRecords,
                             1,  // num_uuid,
                             &uuid, 0, nullptr)) {
      LOG(ERROR) << __func__ << " Unable to initialize sdp discovery";
      return -1;
    }

    std::promise<uint16_t> promise;
    auto future = promise.get_future();

    if (!SDP_ServiceSearchAttributeRequest2(raw_address, sdp_discovery_db,
                                            bta_jv_start_discovery_callback,
                                            (void*)&promise)) {
      LOG(ERROR) << __func__
                 << " Failed to start search attribute request.. waiting";
      return -2;
    }
    uint16_t result = future.get();
    LOG(INFO) << __func__ << " connection result:" << result;

    tSDP_DISC_REC* rec =
        SDP_FindServiceInDb(sdp_discovery_db, uuid.As16Bit(), nullptr);
    if (rec == nullptr) {
      LOG(INFO) << __func__ << " iter:" << i << " discovery record is null"
                << " from:" << raw_address.ToString() << " uuid:" << uuid;
    } else {
      printf("iter:%d result:%d attr_id:%x from:%s uuid:%s", i, result,
             rec->p_first_attr->attr_id, rec->remote_bd_addr.ToString().c_str(),
             uuid.ToString().c_str());

      LOG(INFO) << __func__ << " iter:" << i << " result:" << result
                << " discovery record found  attr_id:"
                << rec->p_first_attr->attr_id
                << " len_type:" << rec->p_first_attr->attr_len_type << " time"
                << rec->time_read << " from:" << rec->remote_bd_addr.ToString()
                << " uuid:" << uuid;
      fflush(nullptr);
    }
    free(sdp_discovery_db);
  }
  return 0;
}

int main(int argc, char** argv) {
  printf("Hello world\n");
  fflush(nullptr);

  LOG(INFO) << "bt_headless start up";

  bluetooth::test::headless::GetOpt options(argc, argv);
  if (!options.IsValid()) {
    return -1;
  }
  if (options.loop_ < 1) {
    LOG(INFO) << "This test requires at least a single loop";
    options.Usage();
    return -1;
  }
  if (options.device_.size() != 1) {
    LOG(INFO) << "This test requires a single device specified";
    options.Usage();
    return -1;
  }
  if (options.uuid_.size() != 1) {
    LOG(INFO) << "This test requires a single uuid specified";
    options.Usage();
    return -1;
  }

  bluetooth::test::headless::Test test;
  int rc = test.Run<int>([options]() {
    return sdp_query_uuid(options.loop_, options.device_.front(),
                          options.uuid_.front());
  });
  LOG(INFO) << "bt_headless shut down";
  return rc;
}
