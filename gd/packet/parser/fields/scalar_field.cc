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

const std::string ScalarField::kFieldType = "ScalarField";

ScalarField::ScalarField(std::string name, int size, ParseLocation loc) : PacketField(name, loc), size_(size) {
  if (size_ > 64 || size_ < 0) {
    ERROR(this) << "Not implemented for size_ = " << size_;
  }
}

const std::string& ScalarField::GetFieldType() const {
  return ScalarField::kFieldType;
}

Size ScalarField::GetSize() const {
  return size_;
}

std::string ScalarField::GetDataType() const {
  return util::GetTypeForSize(size_);
}

void ScalarField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << GetDataType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";
  s << "ASSERT(was_validated_);";

  // Write the Getter Function Body
  int num_leading_bits = 0;
  int field_size = GetSize().bits();

  if (!start_offset.empty()) {
    // Default to start if available.
    num_leading_bits = start_offset.bits() % 8;
    s << "auto it = begin() + " << start_offset.bytes() << " + (" << start_offset.dynamic_string() << ");";
  } else if (!end_offset.empty()) {
    int offset_from_end = end_offset.bits() + field_size;
    num_leading_bits = 8 - (offset_from_end % 8);
    int byte_offset = (7 + offset_from_end) / 8;
    s << "auto it = end() - " << byte_offset << " - (" << end_offset.dynamic_string() << ");";
  } else {
    ERROR(this) << "Ambiguous offset for field.";
  }

  // Extract the correct number of bytes. The return type could be different
  // from the extract type if an earlier field causes the beginning of the
  // current field to start in the middle of a byte.
  std::string extract_type = util::GetTypeForSize(field_size + num_leading_bits);
  s << "auto value = it.extract<" << extract_type << ">();";

  // Right shift the result to remove leading bits.
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

  s << "return static_cast<" << GetDataType() << ">(value);";
  s << "}\n";
}

bool ScalarField::GenBuilderParameter(std::ostream& s) const {
  s << GetDataType() << " " << GetName();
  return true;
}

bool ScalarField::HasParameterValidator() const {
  return util::RoundSizeUp(GetSize().bits()) != GetSize().bits();
}

void ScalarField::GenParameterValidator(std::ostream& s) const {
  s << "ASSERT(" << GetName() << " < "
    << "(static_cast<uint64_t>(1) << " << GetSize().bits() << "));";
}

void ScalarField::GenInserter(std::ostream& s) const {
  if (GetSize().bits() == 8) {
    s << "i.insert_byte(" << GetName() << "_);";
  } else if (GetSize().bits() % 8 == 0) {
    s << "insert(" << GetName() << "_, i);";
  } else {
    s << "insert(" << GetName() << "_, i," << GetSize().bits() << ");";
  }
}

void ScalarField::GenValidator(std::ostream&) const {
  // Do nothing
}
