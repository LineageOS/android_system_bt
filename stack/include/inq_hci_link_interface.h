/*
 *  Copyright 2020 The Android Open Source Project
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
 */

#pragma once

#include <cstdint>

#include <cstdint>

#include "types/raw_address.h"

extern void btm_process_remote_name(const RawAddress* bda, BD_NAME name,
                                    uint16_t evt_len, uint8_t hci_status);

extern void btm_process_inq_results(uint8_t* p, uint8_t hci_evt_len,
                                    uint8_t inq_res_mode);

extern void btm_process_inq_complete(uint8_t status, uint8_t mode);
extern void btm_process_cancel_complete(uint8_t status, uint8_t mode);

extern void btm_acl_process_sca_cmpl_pkt(uint8_t len, uint8_t* data);
extern tINQ_DB_ENT* btm_inq_db_new(const RawAddress& p_bda);
