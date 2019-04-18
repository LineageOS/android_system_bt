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

#include "fields/scalar_field.h"
#include "util.h"

ScalarField::ScalarField(std::string name, int size, ParseLocation loc) : PacketField(loc, name), size_(size) {}

PacketField::Type ScalarField::GetFieldType() const {
  return PacketField::Type::SCALAR;
}

Size ScalarField::GetSize() const {
  return size_;
}

std::string ScalarField::GetType() const {
  return util::GetTypeForSize(size_);
}

void ScalarField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << GetType();
  s << " Get" << GetName() << "() const {";
  s << "ASSERT(was_validated_);";

  // Write the Getter Function Body
  int num_leading_bits = 0;
  int field_size = size_;

  // Handle if to start the iterator at begin or end.
  s << "auto it = ";
  if (!start_offset.empty()) {
    // Default to start if available.
    num_leading_bits = start_offset.bits() % 8;
    s << "begin()";
    if (start_offset.bits() / 8 != 0) s << " + " << start_offset.bits() / 8;
    if (start_offset.has_dynamic()) s << " + " << start_offset.dynamic_string();
  } else if (!end_offset.empty()) {
    num_leading_bits = (8 - ((end_offset.bits() + field_size) % 8)) % 8;
    // Add 7 so it rounds up
    int byte_offset = (7 + end_offset.bits() + field_size) / 8;
    s << "end() - " << byte_offset;
    if (end_offset.has_dynamic()) s << " - (" << end_offset.dynamic_string() << ")";
  } else {
    ERROR(this) << "Ambiguous offset for field.";
  }
  s << ";";

  // We don't need any masking, just return the extracted value.
  if (num_leading_bits == 0 && util::RoundSizeUp(field_size) == field_size) {
    s << "return it.extract<" << util::GetTypeForSize(field_size) << ">();";
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

  // Cast the result if necessary.
  if (extract_type != util::GetTypeForSize(field_size)) {
    s << "return static_cast<" << GetType() << ">(value);";
  } else {
    s << "return value;";
  }
  s << "}\n";
}

bool ScalarField::GenBuilderParameter(std::ostream& s) const {
  if (size_ > 64 || size_ < 0) {
    ERROR(this) << "Not implemented";
  }
  std::string param_type = util::GetTypeForSize(size_);
  s << param_type << " " << util::CamelCaseToUnderScore(GetName());
  return true;
}

bool ScalarField::HasParameterValidator() const {
  const auto bits = GetSize().bits();
  return util::RoundSizeUp(bits) != bits;
}

void ScalarField::GenParameterValidator(std::ostream& s) const {
  const auto bits = GetSize().bits();
  if (util::RoundSizeUp(bits) == bits) {
    return;
  }
  s << "ASSERT(" << util::CamelCaseToUnderScore(GetName()) << " < "
    << "(static_cast<uint64_t>(1) << " << bits << "));";
}

void ScalarField::GenInserter(std::ostream& s) const {
  if (GetSize().bits() == 8) {
    s << "i.insert_byte(" << util::CamelCaseToUnderScore(GetName()) << "_);";
  } else if (GetSize().bits() % 8 == 0) {
    s << "insert(" << util::CamelCaseToUnderScore(GetName()) << "_, i);";
  } else {
    s << "insert(" << util::CamelCaseToUnderScore(GetName()) << "_, i," << GetSize().bits() << ");";
  }
}

void ScalarField::GenValidator(std::ostream&) const {
  // Do nothing since the fixed size fields will be handled seperatly.
}
