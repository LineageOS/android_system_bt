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

#include "hal/snoop_logger.h"

#include <arpa/inet.h>
#include <sys/stat.h>

#include <algorithm>
#include <bitset>
#include <chrono>
#include <sstream>

#include "common/circular_buffer.h"
#include "common/strings.h"
#include "os/files.h"
#include "os/log.h"
#include "os/parameter_provider.h"
#include "os/system_properties.h"

namespace bluetooth {
namespace hal {

namespace {

// Epoch in microseconds since 01/01/0000.
constexpr uint64_t kBtSnoopEpochDelta = 0x00dcddb30f2f8000ULL;

constexpr uint32_t kBytesToTest = 0x12345678;
constexpr uint8_t kFirstByte = (const uint8_t&)kBytesToTest;
constexpr bool isLittleEndian = kFirstByte == 0x78;
constexpr bool isBigEndian = kFirstByte == 0x12;
static_assert(isLittleEndian || isBigEndian && isLittleEndian != isBigEndian);

constexpr uint32_t BTSNOOP_VERSION_NUMBER = isLittleEndian ? 0x01000000 : 1;
constexpr uint32_t BTSNOOP_DATALINK_TYPE =
    isLittleEndian ? 0xea030000 : 0x03ea;  // Datalink Type code for HCI UART (H4) is 1002
uint64_t htonll(uint64_t ll) {
  if constexpr (isLittleEndian) {
    return static_cast<uint64_t>(htonl(ll & 0xffffffff)) << 32 | htonl(ll >> 32);
  } else {
    return ll;
  }
}

constexpr SnoopLogger::FileHeaderType kBtSnoopFileHeader = {
    .identification_pattern = {'b', 't', 's', 'n', 'o', 'o', 'p', 0x00},
    .version_number = BTSNOOP_VERSION_NUMBER,
    .datalink_type = BTSNOOP_DATALINK_TYPE};

// The number of packets per btsnoop file before we rotate to the next file. As of right now there
// are two snoop files that are rotated through. The size can be dynamically configured by setting
// the relevant system property
constexpr size_t kDefaultBtSnoopMaxPacketsPerFile = 0xffff;

// We want to use at most 256 KB memory for btsnooz log
constexpr size_t kDefaultBtsnoozMaxMemoryUsageBytes = 256 * 1024;
// We restrict the maximum packet size to 150 bytes
constexpr size_t kDefaultBtSnoozMaxBytesPerPacket = 150;
constexpr size_t kDefaultBtSnoozMaxPayloadBytesPerPacket =
    kDefaultBtSnoozMaxBytesPerPacket - sizeof(SnoopLogger::PacketHeaderType);
// Calculate max number of packets based on max memory usage and max packet size
constexpr size_t kDefaultBtSnoozMaxPacketsPerBuffer =
    kDefaultBtsnoozMaxMemoryUsageBytes / kDefaultBtSnoozMaxBytesPerPacket;

std::string get_btsnoop_log_path(std::string log_dir, bool filtered) {
  if (filtered) {
    log_dir.append(".filtered");
  }
  return log_dir;
}

std::string get_last_log_path(std::string log_file_path) {
  return log_file_path.append(".last");
}

void delete_btsnoop_files(const std::string& log_path) {
  LOG_INFO("Deleting logs if they exist");
  if (os::FileExists(log_path)) {
    if (!os::RemoveFile(log_path)) {
      LOG_ERROR("Failed to remove main log file at \"%s\"", log_path.c_str());
    }
  } else {
    LOG_INFO("Main log file does not exist at \"%s\"", log_path.c_str());
  }
  auto last_log_path = get_last_log_path(log_path);
  if (os::FileExists(last_log_path)) {
    if (!os::RemoveFile(last_log_path)) {
      LOG_ERROR("Failed to remove last log file at \"%s\"", log_path.c_str());
    }
  } else {
    LOG_INFO("Last log file does not exist at \"%s\"", log_path.c_str());
  }
}

size_t get_btsnooz_packet_length_to_write(const HciPacket& packet, SnoopLogger::PacketType type) {
  static const size_t kAclHeaderSize = 4;
  static const size_t kL2capHeaderSize = 4;
  static const size_t kL2capCidOffset = (kAclHeaderSize + 2);
  static const uint16_t kL2capSignalingCid = 0x0001;

  // Maximum amount of ACL data to log.
  // Enough for an RFCOMM frame up to the frame check;
  // not enough for a HID report or audio data.
  static const size_t kMaxBtsnoozAclSize = 14;

  // Calculate packet length to be included
  size_t included_length = 0;
  switch (type) {
    case SnoopLogger::PacketType::CMD:
    case SnoopLogger::PacketType::EVT:
      included_length = packet.size();
      break;

    case SnoopLogger::PacketType::ACL: {
      // Log ACL and L2CAP header by default
      size_t len_hci_acl = kAclHeaderSize + kL2capHeaderSize;
      // Check if we have enough data for an L2CAP header
      if (packet.size() > len_hci_acl) {
        uint16_t l2cap_cid =
            static_cast<uint16_t>(packet[kL2capCidOffset]) |
            static_cast<uint16_t>((static_cast<uint16_t>(packet[kL2capCidOffset + 1]) << static_cast<uint16_t>(8)));
        if (l2cap_cid == kL2capSignalingCid) {
          // For the signaling CID, take the full packet.
          // That way, the PSM setup is captured, allowing decoding of PSMs down
          // the road.
          return packet.size();
        } else {
          // Otherwise, return as much as we reasonably can
          len_hci_acl = kMaxBtsnoozAclSize;
        }
      }
      included_length = std::min(len_hci_acl, packet.size());
      break;
    }

    case SnoopLogger::PacketType::ISO:
    case SnoopLogger::PacketType::SCO:
    default:
      // We are not logging SCO and ISO packets in snooz log as they may contain voice data
      break;
  }
  return std::min(included_length, kDefaultBtSnoozMaxPayloadBytesPerPacket);
}

}  // namespace

const std::string SnoopLogger::kBtSnoopLogModeDisabled = "disabled";
const std::string SnoopLogger::kBtSnoopLogModeFiltered = "filtered";
const std::string SnoopLogger::kBtSnoopLogModeFull = "full";

const std::string SnoopLogger::kBtSnoopMaxPacketsPerFileProperty = "persist.bluetooth.btsnoopsize";
const std::string SnoopLogger::kIsDebuggableProperty = "ro.debuggable";
const std::string SnoopLogger::kBtSnoopLogModeProperty = "persist.bluetooth.btsnooplogmode";
const std::string SnoopLogger::kBtSnoopDefaultLogModeProperty = "persist.bluetooth.btsnoopdefaultmode";

SnoopLogger::SnoopLogger(
    std::string snoop_log_path,
    std::string snooz_log_path,
    size_t max_packets_per_file,
    const std::string& btsnoop_mode)
    : snoop_log_path_(std::move(snoop_log_path)),
      snooz_log_path_(std::move(snooz_log_path)),
      max_packets_per_file_(max_packets_per_file),
      btsnooz_buffer_(kDefaultBtSnoozMaxPacketsPerBuffer) {
  if (false && btsnoop_mode == kBtSnoopLogModeFiltered) {
    // TODO(b/163733538): implement filtered snoop log in GD, currently filtered == disabled
    LOG_INFO("Filtered Snoop Logs enabled");
    is_enabled_ = true;
    is_filtered_ = true;
    // delete unfiltered logs
    delete_btsnoop_files(get_btsnoop_log_path(snoop_log_path_, false));
    // delete snooz logs
    delete_btsnoop_files(snooz_log_path_);
  } else if (btsnoop_mode == kBtSnoopLogModeFull) {
    LOG_INFO("Snoop Logs fully enabled");
    is_enabled_ = true;
    is_filtered_ = false;
    // delete filtered logs
    delete_btsnoop_files(get_btsnoop_log_path(snoop_log_path_, true));
    // delete snooz logs
    delete_btsnoop_files(snooz_log_path_);
  } else {
    LOG_INFO("Snoop Logs disabled");
    is_enabled_ = false;
    is_filtered_ = false;
    // delete both filtered and unfiltered logs
    delete_btsnoop_files(get_btsnoop_log_path(snoop_log_path_, true));
    delete_btsnoop_files(get_btsnoop_log_path(snoop_log_path_, false));
  }
  // Add ".filtered" extension if necessary
  snoop_log_path_ = get_btsnoop_log_path(snoop_log_path_, is_filtered_);
}

void SnoopLogger::CloseCurrentSnoopLogFile() {
  std::lock_guard<std::recursive_mutex> lock(file_mutex_);
  if (btsnoop_ostream_.is_open()) {
    btsnoop_ostream_.flush();
    btsnoop_ostream_.close();
  }
  packet_counter_ = 0;
}

void SnoopLogger::OpenNextSnoopLogFile() {
  std::lock_guard<std::recursive_mutex> lock(file_mutex_);
  CloseCurrentSnoopLogFile();

  auto last_file_path = get_last_log_path(snoop_log_path_);

  if (os::FileExists(snoop_log_path_)) {
    if (!os::RenameFile(snoop_log_path_, last_file_path)) {
      LOG_ERROR(
          "Unabled to rename existing snoop log from \"%s\" to \"%s\"",
          snoop_log_path_.c_str(),
          last_file_path.c_str());
    }
  } else {
    LOG_INFO("Previous log file \"%s\" does not exist, skip renaming", snoop_log_path_.c_str());
  }

  mode_t prevmask = umask(0);
  // do not use std::ios::app as we want override the existing file
  btsnoop_ostream_.open(snoop_log_path_, std::ios::binary | std::ios::out);
  if (!btsnoop_ostream_.good()) {
    LOG_ALWAYS_FATAL("Unable to open snoop log at \"%s\", error: \"%s\"", snoop_log_path_.c_str(), strerror(errno));
  }
  umask(prevmask);
  if (!btsnoop_ostream_.write(reinterpret_cast<const char*>(&kBtSnoopFileHeader), sizeof(FileHeaderType))) {
    LOG_ALWAYS_FATAL("Unable to write file header to \"%s\", error: \"%s\"", snoop_log_path_.c_str(), strerror(errno));
  }
  if (!btsnoop_ostream_.flush()) {
    LOG_ERROR("Failed to flush, error: \"%s\"", strerror(errno));
  }
}

void SnoopLogger::Capture(const HciPacket& packet, Direction direction, PacketType type) {
  uint64_t timestamp_us =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count();
  std::bitset<32> flags = 0;
  switch (type) {
    case PacketType::CMD:
      flags.set(0, false);
      flags.set(1, true);
      break;
    case PacketType::ACL:
    case PacketType::SCO:
      flags.set(0, direction == Direction::INCOMING);
      flags.set(1, false);
      break;
    case PacketType::EVT:
      flags.set(0, true);
      flags.set(1, true);
      break;
    case PacketType::ISO:
      flags.set(0, direction == Direction::INCOMING);
      flags.set(1, true);
      break;
  }
  uint32_t length = packet.size() + /* type byte */ 1;
  PacketHeaderType header = {.length_original = htonl(length),
                             .length_captured = htonl(length),
                             .flags = htonl(static_cast<uint32_t>(flags.to_ulong())),
                             .dropped_packets = 0,
                             .timestamp = htonll(timestamp_us + kBtSnoopEpochDelta),
                             .type = static_cast<uint8_t>(type)};
  {
    std::lock_guard<std::recursive_mutex> lock(file_mutex_);
    if (!is_enabled_) {
      // btsnoop disabled, log in-memory btsnooz log only
      std::stringstream ss;
      size_t included_length = get_btsnooz_packet_length_to_write(packet, type);
      header.length_captured = htonl(included_length + /* type byte */ 1);
      if (!ss.write(reinterpret_cast<const char*>(&header), sizeof(PacketHeaderType))) {
        LOG_ERROR("Failed to write packet header for btsnooz, error: \"%s\"", strerror(errno));
      }
      if (!ss.write(reinterpret_cast<const char*>(packet.data()), included_length)) {
        LOG_ERROR("Failed to write packet payload for btsnooz, error: \"%s\"", strerror(errno));
      }
      btsnooz_buffer_.Push(ss.str());
      return;
    }
    packet_counter_++;
    if (packet_counter_ > max_packets_per_file_) {
      OpenNextSnoopLogFile();
    }
    if (!btsnoop_ostream_.write(reinterpret_cast<const char*>(&header), sizeof(PacketHeaderType))) {
      LOG_ERROR("Failed to write packet header for btsnoop, error: \"%s\"", strerror(errno));
    }
    if (!btsnoop_ostream_.write(reinterpret_cast<const char*>(packet.data()), packet.size())) {
      LOG_ERROR("Failed to write packet payload for btsnoop, error: \"%s\"", strerror(errno));
    }
    // std::ofstream::flush() pushes user data into kernel memory. The data will be written even if this process
    // crashes. However, data will be lost if there is a kernel panic, which is out of scope of BT snoop log.
    // NOTE: std::ofstream::write() followed by std::ofstream::flush() has similar effect as UNIX write(fd, data, len)
    //       as write() syscall dumps data into kernel memory directly
    if (!btsnoop_ostream_.flush()) {
      LOG_ERROR("Failed to flush, error: \"%s\"", strerror(errno));
    }
  }
}

void SnoopLogger::DumpSnoozLogToFile(const std::vector<std::string>& data) const {
  std::lock_guard<std::recursive_mutex> lock(file_mutex_);
  if (is_enabled_) {
    LOG_DEBUG("btsnoop log is enabled, skip dumping btsnooz log");
    return;
  }

  auto last_file_path = get_last_log_path(snooz_log_path_);

  if (os::FileExists(snooz_log_path_)) {
    if (!os::RenameFile(snooz_log_path_, last_file_path)) {
      LOG_ERROR(
          "Unabled to rename existing snooz log from \"%s\" to \"%s\"",
          snooz_log_path_.c_str(),
          last_file_path.c_str());
    }
  } else {
    LOG_INFO("Previous log file \"%s\" does not exist, skip renaming", snooz_log_path_.c_str());
  }

  mode_t prevmask = umask(0);
  // do not use std::ios::app as we want override the existing file
  std::ofstream btsnooz_ostream(snooz_log_path_, std::ios::binary | std::ios::out);
  if (!btsnooz_ostream.good()) {
    LOG_ALWAYS_FATAL("Unable to open snoop log at \"%s\", error: \"%s\"", snooz_log_path_.c_str(), strerror(errno));
  }
  umask(prevmask);
  if (!btsnooz_ostream.write(reinterpret_cast<const char*>(&kBtSnoopFileHeader), sizeof(FileHeaderType))) {
    LOG_ALWAYS_FATAL("Unable to write file header to \"%s\", error: \"%s\"", snooz_log_path_.c_str(), strerror(errno));
  }
  for (const auto& packet : data) {
    if (!btsnooz_ostream.write(packet.data(), packet.size())) {
      LOG_ERROR("Failed to write packet payload for btsnooz, error: \"%s\"", strerror(errno));
    }
  }
  if (!btsnooz_ostream.flush()) {
    LOG_ERROR("Failed to flush, error: \"%s\"", strerror(errno));
  }
}

void SnoopLogger::ListDependencies(ModuleList* list) {
  // We have no dependencies
}

void SnoopLogger::Start() {
  std::lock_guard<std::recursive_mutex> lock(file_mutex_);
  if (is_enabled_) {
    OpenNextSnoopLogFile();
  }
}

void SnoopLogger::Stop() {
  std::lock_guard<std::recursive_mutex> lock(file_mutex_);
  LOG_DEBUG("Dumping btsnooz log data to %s", snooz_log_path_.c_str());
  DumpSnoozLogToFile(btsnooz_buffer_.Drain());
  LOG_DEBUG("Closing btsnoop log data at %s", snoop_log_path_.c_str());
  CloseCurrentSnoopLogFile();
}

DumpsysDataFinisher SnoopLogger::GetDumpsysData(flatbuffers::FlatBufferBuilder* builder) const {
  LOG_DEBUG("Dumping btsnooz log data to %s", snooz_log_path_.c_str());
  DumpSnoozLogToFile(btsnooz_buffer_.Pull());
  return Module::GetDumpsysData(builder);
}

size_t SnoopLogger::GetMaxPacketsPerFile() {
  // Allow override max packet per file via system property
  auto max_packets_per_file = kDefaultBtSnoopMaxPacketsPerFile;
  {
    auto max_packets_per_file_prop = os::GetSystemProperty(kBtSnoopMaxPacketsPerFileProperty);
    if (max_packets_per_file_prop) {
      auto max_packets_per_file_number = common::Uint64FromString(max_packets_per_file_prop.value());
      if (max_packets_per_file_number) {
        max_packets_per_file = max_packets_per_file_number.value();
      }
    }
  }
  return max_packets_per_file;
}

std::string SnoopLogger::GetBtSnoopMode() {
  // Default mode is DISABLED on user build.
  // In userdebug/eng build, it can also be overwritten by modifying the global setting
  std::string default_mode = kBtSnoopLogModeDisabled;
  {
    auto is_debuggable = os::GetSystemProperty(kIsDebuggableProperty);
    if (is_debuggable.has_value() && common::StringTrim(is_debuggable.value()) == "1") {
      auto default_mode_property = os::GetSystemProperty(kBtSnoopDefaultLogModeProperty);
      if (default_mode_property) {
        default_mode = std::move(default_mode_property.value());
      }
    }
  }

  // Get the actual mode if exist
  std::string btsnoop_mode = default_mode;
  {
    auto btsnoop_mode_prop = os::GetSystemProperty(kBtSnoopLogModeProperty);
    if (btsnoop_mode_prop) {
      btsnoop_mode = std::move(btsnoop_mode_prop.value());
    }
  }
  return btsnoop_mode;
}

const ModuleFactory SnoopLogger::Factory = ModuleFactory([]() {
  return new SnoopLogger(
      os::ParameterProvider::SnoopLogFilePath(),
      os::ParameterProvider::SnoozLogFilePath(),
      GetMaxPacketsPerFile(),
      GetBtSnoopMode());
});

}  // namespace hal
}  // namespace bluetooth
