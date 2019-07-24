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

#include "fields/array_field.h"
#include "util.h"

const std::string ArrayField::kFieldType = "ArrayField";

ArrayField::ArrayField(std::string name, int element_size, int fixed_size, ParseLocation loc)
    : PacketField(name, loc), element_size_(element_size), fixed_size_(fixed_size) {
  if (element_size_ > 64 || element_size_ < 0)
    ERROR(this) << __func__ << ": Not implemented for element size = " << element_size_;
  // Make sure the element_size is a multiple of 8.
  if (element_size % 8 != 0) {
    ERROR(this) << "Can only have arrays with elements that are byte aligned (" << element_size << ")";
  }
}

ArrayField::ArrayField(std::string name, TypeDef* type_def, int fixed_size, ParseLocation loc)
    : PacketField(name, loc), element_size_(type_def->size_), type_def_(type_def), fixed_size_(fixed_size) {
  // If the element type is not variable sized, make sure that it is byte aligned.
  if (type_def_->size_ != -1 && type_def_->size_ % 8 != 0) {
    ERROR(this) << "Can only have arrays with elements that are byte aligned (" << type_def_->size_ << ")";
  }
}

const std::string& ArrayField::GetFieldType() const {
  return ArrayField::kFieldType;
}

Size ArrayField::GetSize() const {
  if (element_size_ != -1) {
    return Size(fixed_size_ * element_size_);
  }
  return Size();
}

Size ArrayField::GetBuilderSize() const {
  if (element_size_ != -1) {
    std::string ret = "(" + std::to_string(fixed_size_) + " * " + std::to_string(element_size_) + ")";
    return ret;
  } else {
    std::string ret = "[this](){ size_t length = 0; for (const auto& elem : " + GetName() +
                      "_) { length += elem.size() * 8; } return length; }()";
    return ret;
  }
}

std::string ArrayField::GetDataType() const {
  if (type_def_ != nullptr) {
    return "std::array<" + type_def_->name_ + "," + std::to_string(fixed_size_) + ">";
  }
  return "std::array<" + util::GetTypeForSize(element_size_) + "," + std::to_string(fixed_size_) + ">";
}

void ArrayField::GenExtractor(std::ostream& s, Size start_offset, Size end_offset) const {
  GenBounds(s, start_offset, end_offset, GetSize());

  s << " auto subview = GetLittleEndianSubview(field_begin, field_end); ";
  s << "auto it = subview.begin();";

  // Add the element size so that we will extract as many elements as we can.
  s << GetDataType() << " ret;";
  if (element_size_ != -1) {
    std::string type = (type_def_ != nullptr) ? type_def_->name_ : util::GetTypeForSize(element_size_);
    s << GetDataType() << "::iterator ret_it = ret.begin();";
    s << "while (it + sizeof(" << type << ") <= subview.end()) {";
    s << "*ret_it = it.extract<" << type << ">();";
    s << "ret_it++;";
    s << "}";
  } else {
    s << "std::size_t ret_idx = 0;";
    s << "while (it < subview.end()) {";
    s << "it = " << type_def_->name_ << "::ParseArray(ret, &ret_idx, it);";
    s << "ret_idx++;";
    s << "}";
  }
}

void ArrayField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << GetDataType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() {";

  GenExtractor(s, start_offset, end_offset);

  s << "return ret;";
  s << "}\n";
}

bool ArrayField::GenBuilderParameter(std::ostream& s) const {
  if (type_def_ != nullptr) {
    s << "const std::array<" << type_def_->GetTypeName() << "," << fixed_size_ << ">& " << GetName();
  } else {
    s << "const std::array<" << util::GetTypeForSize(element_size_) << "," << fixed_size_ << ">& " << GetName();
  }
  return true;
}

bool ArrayField::GenBuilderMember(std::ostream& s) const {
  if (type_def_ != nullptr) {
    s << "std::array<" << type_def_->GetTypeName() << "," << fixed_size_ << "> " << GetName();
  } else {
    s << "std::array<" << util::GetTypeForSize(element_size_) << "," << fixed_size_ << "> " << GetName();
  }
  return true;
}

bool ArrayField::HasParameterValidator() const {
  return false;
}

void ArrayField::GenParameterValidator(std::ostream&) const {
  // Array length is validated by the compiler
}

void ArrayField::GenInserter(std::ostream& s) const {
  s << "for (const auto& val : " << GetName() << "_) {";
  if (IsEnumArray()) {
    s << "insert(static_cast<" << util::GetTypeForSize(type_def_->size_) << ">(val), i, " << type_def_->size_ << ");";
  } else if (IsCustomFieldArray()) {
    if (type_def_->size_ == -1) {
      s << "val.Serialize(i);";
    } else {
      s << "insert(val, i);";
    }
  } else {
    s << "insert(val, i, " << element_size_ << ");";
  }
  s << "}\n";
}

void ArrayField::GenValidator(std::ostream&) const {
  // NOTE: We could check if the element size divides cleanly into the array size, but we decided to forgo that
  // in favor of just returning as many elements as possible in a best effort style.
  //
  // Other than that there is nothing that arrays need to be validated on other than length so nothing needs to
  // be done here.
}

bool ArrayField::IsEnumArray() const {
  return type_def_ != nullptr && type_def_->GetDefinitionType() == TypeDef::Type::ENUM;
}

bool ArrayField::IsCustomFieldArray() const {
  return type_def_ != nullptr && type_def_->GetDefinitionType() == TypeDef::Type::CUSTOM;
}
