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

#include "fields/size_field.h"
#include "util.h"

SizeField::SizeField(std::string name, int size, bool is_count, ParseLocation loc)
    : PacketField(loc, name + (is_count ? "_count" : "_size")), size_(size), is_count_(is_count),
      sized_field_name_(name) {}

PacketField::Type SizeField::GetFieldType() const {
  return (is_count_ ? PacketField::Type::COUNT : PacketField::Type::SIZE);
}

Size SizeField::GetSize() const {
  return size_;
}

std::string SizeField::GetType() const {
  return util::GetTypeForSize(size_);
}

void SizeField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << "protected:";
  s << GetType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";
  s << "ASSERT(was_validated_);";

  // Write the Getter Function Body
  int num_leading_bits = 0;

  // Handle if to start the iterator at begin or end.
  if (!start_offset.empty()) {
    // Default to start if available.
    num_leading_bits = start_offset.bits() % 8;
    s << "auto it = begin() + " << start_offset.bits() / 8 << " + (" << start_offset.dynamic_string() << ");";
  } else if (!end_offset.empty()) {
    int offset_from_end = end_offset.bits() + size_;
    num_leading_bits = 8 - (offset_from_end % 8);
    // Add 7 so it rounds up
    int byte_offset = (7 + offset_from_end) / 8;
    s << "auto it = end() - " << byte_offset << " - (" << end_offset.dynamic_string() << ");";

  } else {
    ERROR(this) << "Ambiguous offset for field.";
  }

  // We don't need any masking, just return the extracted value.
  if (num_leading_bits == 0 && util::RoundSizeUp(size_) == size_) {
    s << "return it.extract<" << GetType() << ">();";
    s << "}\n";
    s << "public:\n";
    return;
  }

  // Extract the correct number of bytes. The return type could be different
  // from the extract type if an earlier field causes the beginning of the
  // current field to start in the middle of a byte.
  std::string extract_type = util::GetTypeForSize(size_ + num_leading_bits);
  s << "auto value = it.extract<" << extract_type << ">();";

  // Right shift the result to remove leading bits.
  if (num_leading_bits != 0) {
    s << "value >>= " << num_leading_bits << ";";
  }

  // Mask the result if necessary.
  if (util::RoundSizeUp(size_) != size_) {
    uint64_t mask = 0;
    for (int i = 0; i < size_; i++) {
      mask <<= 1;
      mask |= 1;
    }
    s << "value &= 0x" << std::hex << mask << std::dec << ";";
  }

  // Cast the result if necessary.
  if (extract_type != util::GetTypeForSize(size_)) {
    s << "return static_cast<" << GetType() << ">(value);";
  } else {
    s << "return value;";
  }
  s << "}\n";
  s << "public:\n";
}

bool SizeField::GenBuilderParameter(std::ostream&) const {
  // There is no builder parameter for a size field
  return false;
}

bool SizeField::HasParameterValidator() const {
  return false;
}

void SizeField::GenParameterValidator(std::ostream&) const {
  // There is no builder parameter for a size field
  // TODO: Check if the payload fits in the packet?
}

void SizeField::GenInserter(std::ostream&) const {
  ERROR(this) << __func__ << ": This should not be called for size fields";
}

void SizeField::GenValidator(std::ostream&) const {
  // Do nothing since the fixed size fields will be handled specially.
}

std::string SizeField::GetSizedFieldName() const {
  return sized_field_name_;
}
