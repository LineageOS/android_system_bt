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

#include "fields/packet_field.h"

PacketField::PacketField(ParseLocation loc, std::string name) : loc_(loc), name_(name) {}

std::string PacketField::GetDebugName() const {
  std::string ret = "";
  switch (GetFieldType()) {
    case Type::GROUP:
      ret = "GROUP";
      break;
    case Type::FIXED_SCALAR:
      ret = "FIXED SCALAR";
      break;
    case Type::FIXED_ENUM:
      ret = "FIXED ENUM";
      break;
    case Type::RESERVED_SCALAR:
      ret = "RESERVED SCALAR";
      break;
    case Type::SCALAR:
      ret = "SCALAR";
      break;
    case Type::ENUM:
      ret = "ENUM";
      break;
    case Type::SIZE:
      ret = "SIZE";
      break;
    case Type::COUNT:
      ret = "COUNT";
      break;
    case Type::BODY:
      ret = "BODY";
      break;
    case Type::PAYLOAD:
      ret = "PAYLOAD";
      break;
    case Type::ARRAY:
      ret = "ARRAY";
      break;
    case Type::CUSTOM:
      ret = "CUSTOM";
      break;
    default:
      std::cerr << "UNKNOWN DEBUG NAME TYPE\n";
      abort();
  }

  return "Field{Type:" + ret + ", Name:" + GetName() + "}";
}

ParseLocation PacketField::GetLocation() const {
  return loc_;
}

std::string PacketField::GetName() const {
  return name_;
}
