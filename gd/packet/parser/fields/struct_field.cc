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

#include "fields/struct_field.h"
#include "util.h"

const std::string StructField::kFieldType = "StructField";

StructField::StructField(std::string name, std::string type_name, int size, ParseLocation loc)
    : PacketField(name, loc), type_name_(type_name), size_(size) {}

const std::string& StructField::GetFieldType() const {
  return StructField::kFieldType;
}

Size StructField::GetSize() const {
  return size_;
}

Size StructField::GetBuilderSize() const {
  if (size_ != -1) {
    return size_;
  } else {
    std::string ret = "(" + GetName() + "_.size() * 8) ";
    return ret;
  }
}

std::string StructField::GetDataType() const {
  return type_name_;
}

void StructField::GenExtractor(std::ostream& s, Size start_offset, Size end_offset) const {
  if (size_ != -1) {
    GenBounds(s, start_offset, end_offset, Size(size_));
  } else {
    GenBounds(s, start_offset, end_offset, Size());
  }
  s << " auto subview = GetLittleEndianSubview(field_begin, field_end); ";
  s << "auto it = subview.begin();";
  s << "std::vector<" << GetDataType() << "> vec;";
  s << GetDataType() << "::Parse(vec, it);";
}

void StructField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  if (size_ != -1) {
    s << GetDataType() << " Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";
  } else {
    s << "std::vector<" << GetDataType() << "> Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";
  }
  s << "ASSERT(was_validated_);";
  GenExtractor(s, start_offset, end_offset);

  if (size_ != -1) {
    s << "return vec[0];";
  } else {
    s << "return vec;";
  }
  s << "}\n";
}

bool StructField::GenBuilderParameter(std::ostream& s) const {
  s << GetDataType() << " " << GetName();
  return true;
}

bool StructField::HasParameterValidator() const {
  return false;
}

void StructField::GenParameterValidator(std::ostream&) const {
  // Validated at compile time.
}

void StructField::GenInserter(std::ostream& s) const {
  s << GetName() << "_.Serialize(i);";
}

void StructField::GenValidator(std::ostream&) const {
  // Do nothing
}
