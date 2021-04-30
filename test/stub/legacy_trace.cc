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

#include <cstdint>

// tLEGACY_TRACE_LEVEL
uint8_t btu_trace_level = 6;
uint8_t appl_trace_level = 6;
uint8_t btif_trace_level = 6;

uint8_t A2DP_SetTraceLevel(uint8_t new_level) { return 0; }
uint8_t AVDT_SetTraceLevel(uint8_t new_level) { return 0; }
uint8_t AVRC_SetTraceLevel(uint8_t new_level) { return 0; }
uint8_t BNEP_SetTraceLevel(uint8_t new_level) { return 0; }
uint8_t BTM_SetTraceLevel(uint8_t new_level) { return 0; }
uint8_t PAN_SetTraceLevel(uint8_t new_level) { return 0; }
uint8_t PORT_SetTraceLevel(uint8_t new_level) { return 0; }
uint8_t SMP_SetTraceLevel(uint8_t new_level) { return 0; }
