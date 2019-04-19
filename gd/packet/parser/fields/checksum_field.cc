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

#include "fields/checksum_field.h"
#include "util.h"

ChecksumField::ChecksumField(std::string name, std::string type_name, int size, ParseLocation loc)
    : PacketField(loc, name), type_name_(type_name), size_(size) {}

PacketField::Type ChecksumField::GetFieldType() const {
  return PacketField::Type::CHECKSUM;
}

Size ChecksumField::GetSize() const {
  return size_;
}

std::string ChecksumField::GetType() const {
  return type_name_;
}

void ChecksumField::GenGetter(std::ostream&, Size, Size) const {}

bool ChecksumField::GenBuilderParameter(std::ostream&) const {
  return false;
}

bool ChecksumField::HasParameterValidator() const {
  return false;
}

void ChecksumField::GenParameterValidator(std::ostream&) const {
  // Do nothing.
}

void ChecksumField::GenInserter(std::ostream& s) const {
  s << "packet::ByteObserver observer = i.UnregisterObserver();";
  s << "insert(static_cast<" << util::GetTypeForSize(size_) << ">(observer.GetValue()), i);";
}

void ChecksumField::GenValidator(std::ostream&) const {
  // Done in packet_def.cc
}
