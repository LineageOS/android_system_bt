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

#include "fields/fixed_field.h"
#include "util.h"

int FixedField::unique_id_ = 0;

FixedField::FixedField(int size, int64_t value, ParseLocation loc)
    : PacketField(loc, "FixedScalar" + std::to_string(unique_id_++)), type_(Type::FIXED_SCALAR), size_(size),
      value_(value) {}

FixedField::FixedField(EnumDef* enum_def, std::string value, ParseLocation loc)
    : PacketField(loc, "FixedScalar" + std::to_string(unique_id_++)), type_(Type::FIXED_ENUM), enum_(enum_def),
      value_(value) {}

PacketField::Type FixedField::GetFieldType() const {
  return type_;
}

Size FixedField::GetSize() const {
  if (type_ == PacketField::Type::FIXED_SCALAR) {
    return size_;
  }

  return enum_->size_;
}

std::string FixedField::GetType() const {
  if (type_ == PacketField::Type::FIXED_SCALAR) {
    return util::GetTypeForSize(size_);
  }

  return enum_->name_;
}

void FixedField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  // Write the Getter Function Definiton
  s << GetType();
  s << " Get" << GetName() << "() const {";

  // Write the Getter Function Body
  int num_leading_bits = 0;
  int field_size = GetSize().bits();

  // Handle if to start the iterator at begin or end.
  if (!start_offset.empty()) {
    // Default to start if available.
    num_leading_bits = start_offset.bits() % 8;
    s << "auto it = begin() + " << start_offset.bytes() << " + (" << start_offset.dynamic_string() << ");";
  } else if (!end_offset.empty()) {
    int offset_from_end = end_offset.bits() + field_size;
    num_leading_bits = 8 - (offset_from_end % 8);
    // Add 7 so it rounds up
    int byte_offset = (7 + offset_from_end) / 8;
    s << "auto it = end() - " << byte_offset << " - (" << end_offset.dynamic_string() << ");";
  } else {
    ERROR(this) << "Ambiguous offset for field.\n";
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

  // Right shift to remove leading bits.
  if (num_leading_bits != 0) {
    s << "value >>= " << num_leading_bits << ";";
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

  // Cast the result if necessary.
  if (extract_type != GetType()) {
    s << "return static_cast<" << GetType() << ">(value);";
  } else {
    s << "return value;";
  }
  s << "}\n";
}

bool FixedField::GenBuilderParameter(std::ostream&) const {
  // No parameter needed for a fixed field.
  return false;
}

bool FixedField::HasParameterValidator() const {
  return false;
}

void FixedField::GenParameterValidator(std::ostream&) const {
  // No parameter validator needed for a fixed field.
}

void FixedField::GenInserter(std::ostream& s) const {
  s << "insert(";
  if (type_ == PacketField::Type::FIXED_SCALAR) {
    GenValue(s);
  } else {
    s << "static_cast<" << util::GetTypeForSize(GetSize().bits()) << ">(";
    GenValue(s);
    s << ")";
  }
  s << ", i , " << GetSize().bits() << ");";
}

void FixedField::GenValidator(std::ostream& s) const {
  s << "if (Get" << GetName() << "() != ";
  GenValue(s);
  s << ") return false;";
}

void FixedField::GenValue(std::ostream& s) const {
  if (type_ == PacketField::Type::FIXED_SCALAR) {
    s << std::get<int64_t>(value_);
  } else {
    s << enum_->name_ << "::" << std::get<std::string>(value_);
  }
}
