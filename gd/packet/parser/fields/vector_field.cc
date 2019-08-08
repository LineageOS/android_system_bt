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
#include "util.h"

const std::string VectorField::kFieldType = "VectorField";

VectorField::VectorField(std::string name, int element_size, std::string size_modifier, ParseLocation loc)
    : PacketField(name, loc), element_size_(element_size), size_modifier_(size_modifier) {
  if (element_size_ > 64 || element_size_ < 0)
    ERROR(this) << __func__ << ": Not implemented for element size = " << element_size_;
  // Make sure the element_size is a multiple of 8.
  if (element_size % 8 != 0) {
    ERROR(this) << "Can only have arrays with elements that are byte aligned (" << element_size << ")";
  }
}

VectorField::VectorField(std::string name, TypeDef* type_def, std::string size_modifier, ParseLocation loc)
    : PacketField(name, loc), element_size_(type_def->size_), type_def_(type_def), size_modifier_(size_modifier) {
  // If the element type is not variable sized, make sure that it is byte aligned.
  if (type_def_->size_ != -1 && type_def_->size_ % 8 != 0) {
    ERROR(this) << "Can only have arrays with elements that are byte aligned (" << type_def_->size_ << ")";
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

  // size_field_ is of type COUNT and it is a scalar array
  if (type_def_ == nullptr) {
    return "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * " + std::to_string(element_size_) + ")";
  }

  if (IsCustomFieldArray() || IsStructArray()) {
    if (type_def_->size_ != -1) {
      return "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * " + std::to_string(type_def_->size_) +
             ")";
    } else {
      return Size();
    }
  }

  // size_field_ is of type COUNT and it is an enum array
  return "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * " + std::to_string(type_def_->size_) +
         ")";
}

Size VectorField::GetBuilderSize() const {
  if (element_size_ != -1) {
    std::string ret = "(" + GetName() + "_.size() * " + std::to_string(element_size_) + ")";
    return ret;
  } else {
    std::string ret = "[this](){ size_t length = 0; for (const auto& elem : " + GetName() +
                      "_) { length += elem.size() * 8; } return length; }()";
    return ret;
  }
}

std::string VectorField::GetDataType() const {
  if (type_def_ != nullptr) {
    return "std::vector<" + type_def_->name_ + ">";
  }
  return "std::vector<" + util::GetTypeForSize(element_size_) + ">";
}

void VectorField::GenExtractor(std::ostream& s, Size start_offset, Size end_offset) const {
  GenBounds(s, start_offset, end_offset, GetSize());

  s << " auto subview = GetLittleEndianSubview(field_begin, field_end); ";
  s << "auto it = subview.begin();";

  // Add the element size so that we will extract as many elements as we can.
  s << GetDataType() << " ret;";
  if (element_size_ != -1) {
    std::string type = (type_def_ != nullptr) ? type_def_->name_ : util::GetTypeForSize(element_size_);
    s << "while (it + sizeof(" << type << ") <= subview.end()) {";
    s << "ret.push_back(it.extract<" << type << ">());";
    s << "}";
  } else {
    s << "while (it < subview.end()) {";
    s << "it = " << type_def_->name_ << "::Parse(ret, it);";
    s << "}";
  }
}

void VectorField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  s << GetDataType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() {";
  s << "ASSERT(was_validated_);";
  s << "size_t end_index = size();";

  GenExtractor(s, start_offset, end_offset);

  s << "return ret;";
  s << "}\n";
}

bool VectorField::GenBuilderParameter(std::ostream& s) const {
  if (type_def_ != nullptr) {
    s << "const std::vector<" << type_def_->GetTypeName() << ">& " << GetName();
  } else {
    s << "const std::vector<" << util::GetTypeForSize(element_size_) << ">& " << GetName();
  }
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
  s << "for (const auto& val : " << GetName() << "_) {";
  if (IsEnumArray()) {
    s << "insert(static_cast<" << util::GetTypeForSize(type_def_->size_) << ">(val), i, " << type_def_->size_ << ");";
  } else if (IsCustomFieldArray()) {
    if (type_def_->size_ == -1) {
      s << "val.Serialize(i);";
    } else {
      s << "insert(val, i);";
    }
  } else if (IsStructArray()) {
    s << "val.Serialize(i);";
  } else {
    s << "insert(val, i, " << element_size_ << ");";
  }
  s << "}\n";
}

void VectorField::GenValidator(std::ostream&) const {
  // NOTE: We could check if the element size divides cleanly into the array size, but we decided to forgo that
  // in favor of just returning as many elements as possible in a best effort style.
  //
  // Other than that there is nothing that arrays need to be validated on other than length so nothing needs to
  // be done here.
}

bool VectorField::IsEnumArray() const {
  return type_def_ != nullptr && type_def_->GetDefinitionType() == TypeDef::Type::ENUM;
}

bool VectorField::IsCustomFieldArray() const {
  return type_def_ != nullptr && type_def_->GetDefinitionType() == TypeDef::Type::CUSTOM;
}

bool VectorField::IsStructArray() const {
  return type_def_ != nullptr && type_def_->GetDefinitionType() == TypeDef::Type::STRUCT;
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
