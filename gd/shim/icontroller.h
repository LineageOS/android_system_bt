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

#include <cstdint>
#include <string>

/**
 * The shim controller module that depends on the Gd controller module
 */
namespace bluetooth {
namespace shim {

typedef struct {
  uint16_t le_data_packet_length;
  uint8_t total_num_le_packets;
} LeBufferSize;

typedef struct {
  uint16_t supported_max_tx_octets;
  uint16_t supported_max_tx_time;
  uint16_t supported_max_rx_octets;
  uint16_t supported_max_rx_time;
} LeMaximumDataLength;

struct IController {
  virtual bool IsCommandSupported(int op_code) const = 0;
  virtual LeBufferSize GetControllerLeBufferSize() const = 0;
  virtual LeMaximumDataLength GetControllerLeMaximumDataLength() const = 0;
  virtual std::string GetControllerMacAddress() const = 0;
  virtual uint16_t GetControllerAclPacketLength() const = 0;
  virtual uint16_t GetControllerNumAclPacketBuffers() const = 0;
  virtual uint64_t GetControllerLeLocalSupportedFeatures() const = 0;
  virtual uint64_t GetControllerLeSupportedStates() const = 0;
  virtual uint64_t GetControllerLocalExtendedFeatures(uint8_t page_number) const = 0;
  virtual uint8_t GetControllerLeNumberOfSupportedAdverisingSets() const = 0;
  virtual uint8_t GetControllerLocalExtendedFeaturesMaxPageNumber() const = 0;
  virtual ~IController() {}
};

}  // namespace shim
}  // namespace bluetooth
