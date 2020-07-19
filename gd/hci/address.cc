/******************************************************************************
 *
 *  Copyright 2019 The Android Open Source Project
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
 ******************************************************************************/

#include "hci/address.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <sstream>

#include "common/strings.h"

namespace bluetooth {
namespace hci {

const Address Address::kAny{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
const Address Address::kEmpty{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

// Address cannot initialize member variables as it is a POD type
// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
Address::Address(const uint8_t (&addr)[6]) {
  std::copy(addr, addr + kLength, data());
}

Address::Address(std::initializer_list<uint8_t> l) {
  std::copy(l.begin(), std::min(l.begin() + kLength, l.end()), data());
}

std::string Address::ToString() const {
  std::stringstream ss;
  for (auto it = address.rbegin(); it != address.rend(); it++) {
    ss << std::nouppercase << std::hex << std::setw(2) << std::setfill('0') << +*it;
    if (std::next(it) != address.rend()) {
      ss << ':';
    }
  }
  return ss.str();
}

bool Address::FromString(const std::string& from, Address& to) {
  Address new_addr{};
  if (from.length() != 17) {
    return false;
  }

  std::istringstream stream(from);
  std::string token;
  int index = 0;
  while (getline(stream, token, ':')) {
    if (index >= 6) {
      return false;
    }

    if (token.length() != 2) {
      return false;
    }

    char* temp = nullptr;
    new_addr.address.at(5 - index) = std::strtol(token.c_str(), &temp, 16);
    if (temp == token.c_str()) {
      // string token is empty or has wrong format
      return false;
    }
    if (temp != (token.c_str() + token.size())) {
      // cannot parse whole string
      return false;
    }

    index++;
  }

  if (index != 6) {
    return false;
  }

  to = new_addr;
  return true;
}

size_t Address::FromOctets(const uint8_t* from) {
  std::copy(from, from + kLength, data());
  return kLength;
};

bool Address::IsValidAddress(const std::string& address) {
  Address tmp{};
  return Address::FromString(address, tmp);
}

}  // namespace hci
}  // namespace bluetooth
