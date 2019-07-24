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
  s << " // start_offset = " << start_offset.ToString() << "\n";
  s << " // end_offset = " << end_offset.ToString() << "\n";
}

void StructField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  if (size_ != -1) {
    s << GetDataType();
  } else {
    s << "std::vector<" << GetDataType() << ">";
  }
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";

  s << "auto it = ";
  if (!start_offset.empty()) {
    // Default to start if available.
    if (start_offset.bits() % 8 != 0) {
      ERROR(this) << "Struct Field must be byte aligned. start_offset.bits = " << start_offset.bits();
    }
    s << "begin() + (" << start_offset << ") / 8;";
  } else if (size_ != -1) {
    // If the size of the field is already known, we can determine it's offset based on end().
    if (!end_offset.empty()) {
      if (end_offset.bits() % 8) {
        ERROR(this) << "Struct Field must be byte aligned. end_offset.bits = " << end_offset.bits();
      }

      s << "end() - (" << size_ << " + " << end_offset << ") / 8;";
    } else {
      ERROR(this) << "Ambiguous offset for fixed size custom field.";
    }
  } else {
    ERROR(this) << "Struct Field offset can not be determined from begin().";
  }

  s << "std::vector<" << GetDataType() << "> to_return;";
  s << GetDataType() << "::Parse(to_return, it);";
  if (size_ != -1) {
    s << "return to_return[0];";
  } else {
    s << "return to_return;";
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
