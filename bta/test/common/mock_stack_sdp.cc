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
 */

#include <string.h>

#include "bt_target.h"

#include "sdp_api.h"

#include "osi/include/osi.h"

using bluetooth::Uuid;

bool SDP_InitDiscoveryDb(tSDP_DISCOVERY_DB* p_db, uint32_t len,
                         uint16_t num_uuid, const Uuid* p_uuid_list,
                         uint16_t num_attr, uint16_t* p_attr_list) {
  return false;
}

bool SDP_CancelServiceSearch(tSDP_DISCOVERY_DB* p_db) { return false; }

bool SDP_ServiceSearchRequest(const RawAddress& p_bd_addr,
                              tSDP_DISCOVERY_DB* p_db,
                              tSDP_DISC_CMPL_CB* p_cb) {
  return false;
}

bool SDP_ServiceSearchAttributeRequest(const RawAddress& p_bd_addr,
                                       tSDP_DISCOVERY_DB* p_db,
                                       tSDP_DISC_CMPL_CB* p_cb) {
  return false;
}
bool SDP_ServiceSearchAttributeRequest2(const RawAddress& p_bd_addr,
                                        tSDP_DISCOVERY_DB* p_db,
                                        tSDP_DISC_CMPL_CB2* p_cb2,
                                        void* user_data) {
  return false;
}

tSDP_DISC_ATTR* SDP_FindAttributeInRec(tSDP_DISC_REC* p_rec, uint16_t attr_id) {
  return (NULL);
}

bool SDP_FindServiceUUIDInRec(tSDP_DISC_REC* p_rec, Uuid* p_uuid) {
  return false;
}

bool SDP_FindServiceUUIDInRec_128bit(tSDP_DISC_REC* p_rec, Uuid* p_uuid) {
  return false;
}

tSDP_DISC_REC* SDP_FindServiceInDb(tSDP_DISCOVERY_DB* p_db,
                                   uint16_t service_uuid,
                                   tSDP_DISC_REC* p_start_rec) {
  return (NULL);
}

tSDP_DISC_REC* SDP_FindServiceInDb_128bit(tSDP_DISCOVERY_DB* p_db,
                                          tSDP_DISC_REC* p_start_rec) {
  return (NULL);
}

tSDP_DISC_REC* SDP_FindServiceUUIDInDb(tSDP_DISCOVERY_DB* p_db,
                                       const Uuid& uuid,
                                       tSDP_DISC_REC* p_start_rec) {
  return (NULL);
}

bool SDP_FindProtocolListElemInRec(tSDP_DISC_REC* p_rec, uint16_t layer_uuid,
                                   tSDP_PROTOCOL_ELEM* p_elem) {
  return (false);
}

bool SDP_FindProfileVersionInRec(tSDP_DISC_REC* p_rec, uint16_t profile_uuid,
                                 uint16_t* p_version) {
  return (false);
}

uint16_t SDP_DiDiscover(const RawAddress& remote_device,
                        tSDP_DISCOVERY_DB* p_db, uint32_t len,
                        tSDP_DISC_CMPL_CB* p_cb) {
  return 0;
}

uint8_t SDP_GetNumDiRecords(tSDP_DISCOVERY_DB* p_db) { return 0; }

uint16_t SDP_GetDiRecord(uint8_t get_record_index,
                         tSDP_DI_GET_RECORD* p_device_info,
                         tSDP_DISCOVERY_DB* p_db) {
  return 0;
}
uint16_t SDP_SetLocalDiRecord(tSDP_DI_RECORD* p_device_info,
                              uint32_t* p_handle) {
  return 0;
}
uint8_t SDP_SetTraceLevel(uint8_t new_level) { return 0; }
