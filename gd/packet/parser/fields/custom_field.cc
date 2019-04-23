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

#include "fields/custom_field.h"
#include "util.h"

CustomField::CustomField(std::string name, std::string type_name, ParseLocation loc)
    : PacketField(loc, name), type_name_(type_name) {}

// Fixed size custom fields.
CustomField::CustomField(std::string name, std::string type_name, int size, ParseLocation loc)
    : PacketField(loc, name), type_name_(type_name), size_(size) {}

PacketField::Type CustomField::GetFieldType() const {
  return PacketField::Type::CUSTOM;
}

Size CustomField::GetSize() const {
  return size_;
}

std::string CustomField::GetType() const {
  return type_name_;
}

void CustomField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << GetType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";

  s << "auto it = ";
  if (!start_offset.empty()) {
    // Default to start if available.
    if (start_offset.bits() % 8 != 0) {
      ERROR(this) << "Custom Field must be byte aligned.";
    }
    s << "begin()";
    if (start_offset.bits() / 8 != 0) s << " + " << start_offset.bits() / 8;
    if (start_offset.has_dynamic()) s << " + " << start_offset.dynamic_string();
  } else if (size_ != -1) {
    // If the size of the custom field is already known, we can determine it's offset based on end().
    if (!end_offset.empty()) {
      if (end_offset.bits() % 8) {
        ERROR(this) << "Custom Field must be byte aligned.";
      }

      int byte_offset = (end_offset.bits() + size_) / 8;
      s << "end() - " << byte_offset;
      if (end_offset.has_dynamic()) s << " - (" << end_offset.dynamic_string() << ")";
    } else {
      ERROR(this) << "Ambiguous offset for fixed size custom field.";
    }
  } else {
    ERROR(this) << "Custom Field offset can not be determined from begin().";
  }
  s << ";";

  s << "return it.extract<" << GetType() << ">();";
  s << "}\n";
}

bool CustomField::GenBuilderParameter(std::ostream& s) const {
  s << GetType() << " " << GetName();
  return true;
}

bool CustomField::HasParameterValidator() const {
  return false;
}

void CustomField::GenParameterValidator(std::ostream&) const {
  // Do nothing.
}

void CustomField::GenInserter(std::ostream& s) const {
  s << "insert(" << GetName() << "_, i);";
}

void CustomField::GenValidator(std::ostream&) const {
  // Do nothing.
}
