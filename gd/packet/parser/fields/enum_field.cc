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

#include "fields/enum_field.h"

#include "util.h"

EnumField::EnumField(std::string name, EnumDef enum_def, std::string value, ParseLocation loc)
    : PacketField(loc, name), enum_def_(enum_def), value_(value) {}

EnumDef EnumField::GetEnumDef() {
  return enum_def_;
}

PacketField::Type EnumField::GetFieldType() const {
  return PacketField::Type::ENUM;
}

Size EnumField::GetSize() const {
  return enum_def_.size_;
}

std::string EnumField::GetType() const {
  return enum_def_.name_;
}

void EnumField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << GetType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";
  s << "ASSERT(was_validated_);";

  // Write the Getter Function Body
  int num_leading_bits = 0;
  int field_size = enum_def_.size_;

  // Start from the beginning, if possible.
  if (!start_offset.empty()) {
    num_leading_bits = start_offset.bits() % 8;
    s << "auto it = begin()"
      << " + " << start_offset.bytes() << " + (" << start_offset.dynamic_string() << ");";
  } else if (!end_offset.empty()) {
    int offset_from_end = end_offset.bits() + field_size;
    num_leading_bits = 8 - (offset_from_end % 8);
    int byte_offset = (7 + offset_from_end) / 8;
    s << "auto it = end() - " << byte_offset << " - (" << end_offset.dynamic_string() << ");";
  } else {
    ERROR(this) << "Ambiguous offset for field.";
  }

  // We don't need any masking, just return the extracted value.
  if (num_leading_bits == 0 && util::RoundSizeUp(field_size) == field_size) {
    s << "return it.extract<" << GetType() << ">();";
    s << "}\n";
    return;
  }

  // Extract the correct number of bytes. The return type could be different
  // from the extract type if an earlier field causes the beginning of the
  // current field to start in the middle of a byte.
  std::string extract_type = util::GetTypeForSize(field_size + num_leading_bits);
  s << "auto value = it.extract<" << extract_type << ">();";

  // Right shift the result if necessary.
  int shift_amount = num_leading_bits;
  if (shift_amount != 0) {
    s << "value >>= " << shift_amount << ";";
  }

  // Mask the result if necessary.
  if (util::RoundSizeUp(field_size) != field_size) {
    uint64_t mask = 0;
    for (int i = 0; i < field_size; i++) {
      mask <<= 1;
      mask |= 1;
    }
    s << "value &= 0x" << std::hex << mask << std::dec << ";";
  }

  s << "return static_cast<" << GetType() << ">(value);";
  s << "}\n";
}

bool EnumField::GenBuilderParameter(std::ostream& s) const {
  s << GetType() << " " << GetName();
  return true;
}

bool EnumField::HasParameterValidator() const {
  return false;
}

void EnumField::GenParameterValidator(std::ostream&) const {
  // Validated at compile time.
}

void EnumField::GenInserter(std::ostream& s) const {
  s << "insert(static_cast<" << util::GetTypeForSize(GetSize().bits()) << ">(";
  s << GetName() << "_), i, " << GetSize().bits() << ");";
}

void EnumField::GenValidator(std::ostream&) const {
  // Do nothing
}
