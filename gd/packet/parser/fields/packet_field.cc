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

PacketField::PacketField(std::string name, ParseLocation loc) : loc_(loc), name_(name) {}

std::string PacketField::GetDebugName() const {
  return "Field{Type:" + GetFieldType() + ", Name:" + GetName() + "}";
}

ParseLocation PacketField::GetLocation() const {
  return loc_;
}

std::string PacketField::GetName() const {
  return name_;
}

Size PacketField::GetBuilderSize() const {
  return GetSize();
}

bool PacketField::GenBuilderMember(std::ostream& s) const {
  return GenBuilderParameter(s);
}
