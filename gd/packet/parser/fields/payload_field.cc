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

#include "fields/payload_field.h"
#include "util.h"

PayloadField::PayloadField(std::string modifier, ParseLocation loc)
    : PacketField(loc, "Payload"), size_field_(nullptr), size_modifier_(modifier) {}

void PayloadField::SetSizeField(const SizeField* size_field) {
  if (size_field_ != nullptr) {
    ERROR(this, size_field_, size_field) << "The size field for the payload has already been assigned.";
  }

  if (size_field->GetFieldType() == PacketField::Type::COUNT) {
    ERROR(this, size_field) << "Can not use count field to describe a payload.";
  }

  size_field_ = size_field;
}

PacketField::Type PayloadField::GetFieldType() const {
  return PacketField::Type::PAYLOAD;
}

Size PayloadField::GetSize() const {
  if (size_field_ == nullptr) {
    // Require a size field if there is a modifier.
    if (!size_modifier_.empty()) {
      ERROR(this) << "Missing size field for payload with size modifier.";
    }

    return Size();
  }

  std::string dynamic_size = "Get" + size_field_->GetName() + "()";
  if (!size_modifier_.empty()) {
    dynamic_size += size_modifier_;
  }

  return dynamic_size;
}

std::string PayloadField::GetType() const {
  return "PacketView";
}

void PayloadField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  // Write the Getter Function Body
  if (start_offset.empty()) {
    ERROR(this) << "Can not have a payload that has an ambiguous start offset. "
                << "Is there a field with an unknown length before the "
                << "payload?\n";
  }

  if (start_offset.bits() % 8 != 0 && !GetSize().empty()) {
    ERROR(this) << "Can not have a sized payload field "
                << "at a non byte-aligned offset.\n";
  }

  if (GetSize().empty() && end_offset.empty()) {
    ERROR(this) << "Ambiguous end offset for payload with no defined size.";
  }

  s << "PacketView<kLittleEndian> GetPayload() {";

  s << "size_t payload_begin = " << start_offset.bits() / 8 << " + (" << start_offset.dynamic_string() << ");";

  // If the payload is sized, use the size + payload_begin for payload_end, otherwise use the end_offset.
  if (!GetSize().empty()) {
    // If the size isn't empty then it must have a dynamic string only.
    s << "size_t payload_end = payload_begin + (" << GetSize().dynamic_string() << ");";
  } else {
    s << "size_t payload_end = size() - " << end_offset.bits() / 8 << " - (" << end_offset.dynamic_string() << ");";
  }

  s << "return GetLittleEndianSubview(payload_begin, payload_end);";
  s << "}\n\n";

  s << "PacketView<!kLittleEndian> GetPayloadBigEndian() {";

  s << "size_t payload_begin = " << start_offset.bits() / 8 << " + (" << start_offset.dynamic_string() << ");";

  // If the payload is sized, use the size + payload_begin for payload_end, otherwise use the end_offset.
  if (!GetSize().empty()) {
    // If the size isn't empty then it must have a dynamic string only.
    s << "size_t payload_end = payload_begin + (" << GetSize().dynamic_string() << ");";
  } else {
    s << "size_t payload_end = size() - " << end_offset.bits() / 8 << " - (" << end_offset.dynamic_string() << ");";
  }

  s << "return GetBigEndianSubview(payload_begin, payload_end);";
  s << "}\n";
}

bool PayloadField::GenBuilderParameter(std::ostream& s) const {
  s << "std::unique_ptr<BasePacketBuilder> " << util::CamelCaseToUnderScore(GetName());
  return true;
}

bool PayloadField::HasParameterValidator() const {
  return false;
}

void PayloadField::GenParameterValidator(std::ostream&) const {
  // There is no validation needed for a payload
}

void PayloadField::GenInserter(std::ostream&) const {
  ERROR() << __func__ << " Should never be called.";
}

void PayloadField::GenValidator(std::ostream&) const {
  // Do nothing
}
