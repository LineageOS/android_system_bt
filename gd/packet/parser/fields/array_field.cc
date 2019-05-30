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

ArrayField::ArrayField(std::string name, int element_size, std::string size_modifier, ParseLocation loc)
    : PacketField(loc, name), element_size_(element_size), size_modifier_(size_modifier) {
  // Make sure the element_size is a multiple of 8.
  if (element_size % 8 != 0) ERROR(this) << "Can only have arrays with elements that are byte aligned.";
}

ArrayField::ArrayField(std::string name, int element_size, int fixed_size, ParseLocation loc)
    : PacketField(loc, name), element_size_(element_size), fixed_size_(fixed_size) {
  // Make sure the element_size is a multiple of 8.
  if (element_size % 8 != 0) ERROR(this) << "Can only have arrays with elements that are byte aligned.";
}

ArrayField::ArrayField(std::string name, TypeDef* type_def, std::string size_modifier, ParseLocation loc)
    : PacketField(loc, name), element_size_(type_def->size_), type_def_(type_def), size_modifier_(size_modifier) {
  // If it is an enum array, make sure that the enum definition is byte aligned.
  if (type_def_->size_ % 8 != 0) ERROR(this) << "Can only have arrays with elements that are byte aligned.";
}

ArrayField::ArrayField(std::string name, TypeDef* type_def, int fixed_size, ParseLocation loc)
    : PacketField(loc, name), element_size_(type_def->size_), type_def_(type_def), fixed_size_(fixed_size) {
  // If it is an enum array, make sure that the enum definition is byte aligned.
  if (type_def_->size_ % 8 != 0) ERROR(this) << "Can only have arrays with elements that are byte aligned.";
}

PacketField::Type ArrayField::GetFieldType() const {
  return PacketField::Type::ARRAY;
}

Size ArrayField::GetSize() const {
  if (IsFixedSize() && element_size_ != -1) {
    return Size(fixed_size_ * element_size_);
  }

  // If there is no size field, then it is of unknown size.
  if (size_field_ == nullptr) {
    return Size();
  }

  // size_field_ is of type SIZE
  if (size_field_->GetFieldType() == PacketField::Type::SIZE) {
    std::string ret = "Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "()";
    if (!size_modifier_.empty()) ret += size_modifier_;
    return ret;
  }

  // size_field_ is of type COUNT and it is a scalar array
  if (!IsEnumArray() && !IsCustomFieldArray()) {
    return "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * " + std::to_string(element_size_ / 8) +
           ")";
  }

  if (IsCustomFieldArray()) {
    return "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * " +
           std::to_string(type_def_->size_ / 8) + ")";
  }

  // size_field_ is of type COUNT and it is an enum array
  return "(Get" + util::UnderscoreToCamelCase(size_field_->GetName()) + "() * " + std::to_string(type_def_->size_ / 8) +
         ")";
}

std::string ArrayField::GetType() const {
  if (type_def_ != nullptr) {
    return "std::vector<" + type_def_->name_ + ">";
  }
  return "std::vector<" + util::GetTypeForSize(element_size_) + ">";
}

void ArrayField::GenGetter(std::ostream& s, Size start_offset, Size end_offset) const {
  if (start_offset.empty()) {
    ERROR(this) << "Can not have an array with an ambiguous start offset.";
  }

  if (start_offset.bits() % 8 != 0) {
    ERROR(this) << "Can not have an array that isn't byte aligned.";
  }

  if (GetSize().empty() && end_offset.empty()) {
    ERROR(this) << "Ambiguous end offset for array with no defined size.";
  }

  s << GetType();
  s << " Get" << util::UnderscoreToCamelCase(GetName()) << "() {";
  s << "ASSERT(was_validated_);";

  s << "auto it = begin() + " << start_offset.bytes() << " + " << start_offset.dynamic_string() << ";";

  if (!GetSize().empty()) {
    auto size = GetSize();
    s << "auto array_end = it + " << size.bytes() << " /* bytes */ + " << size.dynamic_string() << ";";
  } else {
    s << "auto array_end = end() - " << end_offset.bytes() << " /* bytes */ - " << end_offset.dynamic_string() << ";";
  }

  // Add the element size so that we will extract as many elements as we can.
  s << GetType() << " ret;";
  std::string type = type_def_->name_;
  s << "while (it + sizeof(" << type << ") <= array_end) {";
  s << "ret.push_back(it.extract<" << type << ">());";
  s << "}";

  s << "return ret;";
  s << "}\n";
}

bool ArrayField::GenBuilderParameter(std::ostream& s) const {
  std::string element_type = "";
  if (type_def_ != nullptr) {
    element_type = type_def_->GetTypeName();
  } else {
    if (element_size_ > 64 || element_size_ < 0)
      ERROR(this) << __func__ << ": Not implemented for element size = " << element_size_;
    element_type = util::GetTypeForSize(element_size_);
  }

  s << "const std::vector<" << element_type << ">& " << GetName();
  return true;
}

bool ArrayField::HasParameterValidator() const {
  if (fixed_size_ == -1) {
    // Does not have parameter validator yet.
    // TODO: See comment in GenParameterValidator
    return false;
  }
  return true;
}

void ArrayField::GenParameterValidator(std::ostream& s) const {
  if (fixed_size_ == -1) {
    // No Parameter validator if its dynamically size.
    // TODO: Maybe add a validator to ensure that the size isn't larger than what the size field can hold.
    return;
  }

  s << "ASSERT(" << GetName() << ".size() == " << fixed_size_ << ");";
}

void ArrayField::GenInserter(std::ostream& s) const {
  s << "for (const auto& val : " << GetName() << "_) {";
  if (IsEnumArray()) {
    s << "insert(static_cast<" << util::GetTypeForSize(type_def_->size_) << ">(val), i, " << type_def_->size_ << ");";
  } else if (IsCustomFieldArray()) {
    s << "insert(val, i);";
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

bool ArrayField::IsFixedSize() const {
  return fixed_size_ != -1;
}

void ArrayField::SetSizeField(const SizeField* size_field) {
  if (size_field->GetFieldType() == PacketField::Type::COUNT && !size_modifier_.empty()) {
    ERROR(this, size_field) << "Can not use count field to describe array with a size modifier."
                            << " Use size instead";
  }

  if (IsFixedSize()) {
    ERROR(this, size_field) << "Can not use size field with a fixed size array.";
  }

  size_field_ = size_field;
}

const std::string& ArrayField::GetSizeModifier() const {
  return size_modifier_;
}
