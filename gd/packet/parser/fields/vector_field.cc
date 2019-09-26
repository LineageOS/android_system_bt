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

#include "fields/vector_field.h"

#include "fields/count_field.h"
#include "util.h"

const std::string VectorField::kFieldType = "VectorField";

VectorField::VectorField(std::string name, int element_size, std::string size_modifier, ParseLocation loc)
    : PacketField(name, loc), element_field_(new ScalarField("val", element_size, loc)), element_size_(element_size),
      size_modifier_(size_modifier) {
  if (element_size > 64 || element_size < 0)
    ERROR(this) << __func__ << ": Not implemented for element size = " << element_size;
  if (element_size % 8 != 0) {
    ERROR(this) << "Can only have arrays with elements that are byte aligned (" << element_size << ")";
  }
}

VectorField::VectorField(std::string name, TypeDef* type_def, std::string size_modifier, ParseLocation loc)
    : PacketField(name, loc), element_field_(type_def->GetNewField("val", loc)),
      element_size_(element_field_->GetSize()), size_modifier_(size_modifier) {
  if (!element_size_.empty() && element_size_.bits() % 8 != 0) {
    ERROR(this) << "Can only have arrays with elements that are byte aligned (" << element_size_ << ")";
  }
}

const std::string& VectorField::GetFieldType() const {
  return VectorField::kFieldType;
}

Size VectorField::GetSize() const {
  // If there is no size field, then it is of unknown size.
  if (size_field_ == nullptr) {
    return Size();
  }

  // size_field_ is of type SIZE
  if (size_field_->GetFieldType() == SizeField::kFieldType) {
    std::string ret = "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * 8)";
    if (!size_modifier_.empty()) ret += size_modifier_;
    return ret;
  }

  // size_field_ is of type COUNT and elements have a fixed size
  if (!element_size_.empty() && !element_size_.has_dynamic()) {
    return "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * " +
           std::to_string(element_size_.bits()) + ")";
  }

  return Size();
}

Size VectorField::GetBuilderSize() const {
  if (!element_size_.empty() && !element_size_.has_dynamic()) {
    std::string ret = "(" + GetName() + "_.size() * " + std::to_string(element_size_.bits()) + ")";
    return ret;
  } else {
    std::string ret = "[this](){ size_t length = 0; for (const auto& elem : " + GetName() +
                      "_) { length += elem.size() * 8; } return length; }()";
    return ret;
  }
}

std::string VectorField::GetDataType() const {
  return "std::vector<" + element_field_->GetDataType() + ">";
}

void VectorField::GenExtractor(std::ostream& s, int num_leading_bits) const {
  s << "auto " << element_field_->GetName() << "_it = " << GetName() << "_it;";
  if (!element_size_.empty() && !element_size_.has_dynamic()) {
    s << "while (" << element_field_->GetName() << "_it.NumBytesRemaining() >= " << element_size_.bytes() << ") {";
  } else {
    s << "while (" << element_field_->GetName() << "_it.NumBytesRemaining() > 0) {";
  }
  s << element_field_->GetDataType() << " " << element_field_->GetName() << "_value;";
  s << element_field_->GetDataType() << "* " << element_field_->GetName() << "_ptr = &" << element_field_->GetName()
    << "_value;";
  element_field_->GenExtractor(s, num_leading_bits);
  s << GetName() << "_ptr->push_back(" << element_field_->GetName() << "_value);";
  s << "}";
}

void VectorField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << GetDataType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() {";
  s << "ASSERT(was_validated_);";
  s << "size_t end_index = size();";
  s << "auto to_bound = begin();";

  int num_leading_bits = GenBounds(s, start_offset, end_offset);
  s << GetDataType() << " " << GetName() << "_value;";
  s << GetDataType() << "* " << GetName() << "_ptr = &" << GetName() << "_value;";
  GenExtractor(s, num_leading_bits);

  s << "return " << GetName() << "_value;";
  s << "}\n";
}

bool VectorField::GenBuilderParameter(std::ostream& s) const {
  s << "const std::vector<" << element_field_->GetDataType() << ">& " << GetName();
  return true;
}

bool VectorField::GenBuilderMember(std::ostream& s) const {
  s << "const std::vector<" << element_field_->GetDataType() << "> " << GetName();
  return true;
}

bool VectorField::HasParameterValidator() const {
  // Does not have parameter validator yet.
  // TODO: See comment in GenParameterValidator
  return false;
}

void VectorField::GenParameterValidator(std::ostream&) const {
  // No Parameter validator if its dynamically size.
  // TODO: Maybe add a validator to ensure that the size isn't larger than what the size field can hold.
  return;
}

void VectorField::GenInserter(std::ostream& s) const {
  s << "for (const auto& val_ : " << GetName() << "_) {";
  element_field_->GenInserter(s);
  s << "}\n";
}

void VectorField::GenValidator(std::ostream&) const {
  // NOTE: We could check if the element size divides cleanly into the array size, but we decided to forgo that
  // in favor of just returning as many elements as possible in a best effort style.
  //
  // Other than that there is nothing that arrays need to be validated on other than length so nothing needs to
  // be done here.
}

void VectorField::SetSizeField(const SizeField* size_field) {
  if (size_field->GetFieldType() == CountField::kFieldType && !size_modifier_.empty()) {
    ERROR(this, size_field) << "Can not use count field to describe array with a size modifier."
                            << " Use size instead";
  }

  size_field_ = size_field;
}

const std::string& VectorField::GetSizeModifier() const {
  return size_modifier_;
}
