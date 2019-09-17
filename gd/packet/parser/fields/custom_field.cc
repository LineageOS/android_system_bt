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

const std::string CustomField::kFieldType = "CustomField";

CustomField::CustomField(std::string name, std::string type_name, ParseLocation loc)
    : PacketField(name, loc), type_name_(type_name) {}

const std::string& CustomField::GetFieldType() const {
  return CustomField::kFieldType;
}

Size CustomField::GetSize() const {
  return Size();
}

Size CustomField::GetBuilderSize() const {
  std::string ret = "(" + GetName() + "_.size() * 8) ";
  return ret;
}

std::string CustomField::GetDataType() const {
  return type_name_;
}

void CustomField::GenExtractor(std::ostream& s, Size start_offset, Size end_offset) const {
  GenBounds(s, start_offset, end_offset, Size());
  s << "auto it = begin_it.Subrange(field_begin, field_end - field_begin);";
  s << "std::unique_ptr<" << GetDataType() << "> ptr = std::make_unique<" << GetDataType() << ">();";
  s << GetDataType() << "::Parse(ptr.get(), it);";
}

void CustomField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << "std::unique_ptr<" << GetDataType() << "> Get" << util::UnderscoreToCamelCase(GetName()) << "() const {";
  s << "ASSERT(was_validated_);";
  s << "size_t end_index = size();";
  s << "auto begin_it = begin();";

  GenExtractor(s, start_offset, end_offset);
  s << "return ptr;";
  s << "}\n";
}

bool CustomField::GenBuilderParameter(std::ostream& s) const {
  s << GetDataType() << " " << GetName();
  return true;
}

bool CustomField::HasParameterValidator() const {
  return false;
}

void CustomField::GenParameterValidator(std::ostream&) const {
  // Do nothing.
}

void CustomField::GenInserter(std::ostream& s) const {
  s << GetName() << "_.Serialize(i);";
}

void CustomField::GenValidator(std::ostream&) const {
  // Do nothing.
}
