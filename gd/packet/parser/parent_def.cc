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

#include "parent_def.h"

#include "fields/all_fields.h"
#include "util.h"

ParentDef::ParentDef(std::string name, FieldList fields) : TypeDef(name), fields_(fields), parent_(nullptr){};
ParentDef::ParentDef(std::string name, FieldList fields, ParentDef* parent)
    : TypeDef(name), fields_(fields), parent_(parent){};

void ParentDef::AddParentConstraint(std::string field_name, std::variant<int64_t, std::string> value) {
  // NOTE: This could end up being very slow if there are a lot of constraints.
  const auto& parent_params = parent_->GetParamList();
  const auto& constrained_field = parent_params.GetField(field_name);
  if (constrained_field == nullptr) {
    ERROR() << "Attempting to constrain field " << field_name << " in parent " << parent_->name_
            << ", but no such field exists.";
  }

  if (constrained_field->GetFieldType() == PacketField::Type::SCALAR) {
    if (!std::holds_alternative<int64_t>(value)) {
      ERROR(constrained_field) << "Attemting to constrain a scalar field to an enum value in " << parent_->name_;
    }
  } else if (constrained_field->GetFieldType() == PacketField::Type::ENUM) {
    if (!std::holds_alternative<std::string>(value)) {
      ERROR(constrained_field) << "Attemting to constrain an enum field to a scalar value in " << parent_->name_;
    }
    const auto& enum_def = static_cast<EnumField*>(constrained_field)->GetEnumDef();
    if (!enum_def.HasEntry(std::get<std::string>(value))) {
      ERROR(constrained_field) << "No matching enumeration \"" << std::get<std::string>(value)
                               << "for constraint on enum in parent " << parent_->name_ << ".";
    }

    // For enums, we have to qualify the value using the enum type name.
    value = enum_def.GetTypeName() + "::" + std::get<std::string>(value);
  } else {
    ERROR(constrained_field) << "Field in parent " << parent_->name_ << " is not viable for constraining.";
  }

  parent_constraints_.insert(std::pair(field_name, value));
}

// Assign all size fields to their corresponding variable length fields.
// Will crash if
//  - there aren't any fields that don't match up to a field.
//  - the size field points to a fixed size field.
//  - if the size field comes after the variable length field.
void ParentDef::AssignSizeFields() {
  for (const auto& field : fields_) {
    DEBUG() << "field name: " << field->GetName();

    if (field->GetFieldType() != PacketField::Type::SIZE && field->GetFieldType() != PacketField::Type::COUNT) {
      continue;
    }

    const SizeField* size_field = static_cast<SizeField*>(field);
    // Check to see if a corresponding field can be found.
    const auto& var_len_field = fields_.GetField(size_field->GetSizedFieldName());
    if (var_len_field == nullptr) {
      ERROR(field) << "Could not find corresponding field for size/count field.";
    }

    // Do the ordering check to ensure the size field comes before the
    // variable length field.
    for (auto it = fields_.begin(); *it != size_field; it++) {
      DEBUG() << "field name: " << (*it)->GetName();
      if (*it == var_len_field) {
        ERROR(var_len_field, size_field) << "Size/count field must come before the variable length field it describes.";
      }
    }

    if (var_len_field->GetFieldType() == PacketField::Type::PAYLOAD) {
      const auto& payload_field = static_cast<PayloadField*>(var_len_field);
      payload_field->SetSizeField(size_field);
      continue;
    }

    if (var_len_field->GetFieldType() == PacketField::Type::ARRAY) {
      const auto& array_field = static_cast<ArrayField*>(var_len_field);
      array_field->SetSizeField(size_field);
      continue;
    }

    // If we've reached this point then the field wasn't a variable length field.
    // Check to see if the field is a variable length field
    std::cerr << "Can not use size/count in reference to a fixed size field.\n";
    abort();
  }
}

void ParentDef::SetEndianness(bool is_little_endian) {
  is_little_endian_ = is_little_endian;
}

// Get the size. You scan specify without_payload in order to exclude payload fields as children will be overriding it.
Size ParentDef::GetSize(bool without_payload) const {
  auto size = Size();

  for (const auto& field : fields_) {
    if (without_payload &&
        (field->GetFieldType() == PacketField::Type::PAYLOAD || field->GetFieldType() == PacketField::Type::BODY)) {
      continue;
    }

    // The offset to the field must be passed in as an argument for dynamically sized custom fields.
    if (field->GetFieldType() == PacketField::Type::CUSTOM && field->GetSize().has_dynamic()) {
      std::stringstream custom_field_size;

      // Custom fields are special as their size field takes an argument.
      custom_field_size << field->GetSize().dynamic_string() << "(begin()";

      // Check if we can determine offset from begin(), otherwise error because by this point,
      // the size of the custom field is unknown and can't be subtracted from end() to get the
      // offset.
      auto offset = GetOffsetForField(field->GetName(), false);
      if (offset.empty()) {
        ERROR(field) << "Custom Field offset can not be determined from begin().";
      }

      if (offset.bits() % 8 != 0) {
        ERROR(field) << "Custom fields must be byte aligned.";
      }
      if (offset.has_bits()) custom_field_size << " + " << offset.bits() / 8;
      if (offset.has_dynamic()) custom_field_size << " + " << offset.dynamic_string();
      custom_field_size << ")";

      size += custom_field_size.str();
      continue;
    }

    size += field->GetSize();
  }

  if (parent_ != nullptr) {
    size += parent_->GetSize(true);
  }

  return size;
}

// Get the offset until the field is reached, if there is no field
// returns an empty Size. from_end requests the offset to the field
// starting from the end() iterator. If there is a field with an unknown
// size along the traversal, then an empty size is returned.
Size ParentDef::GetOffsetForField(std::string field_name, bool from_end) const {
  // Check first if the field exists.
  if (fields_.GetField(field_name) == nullptr) {
    if (field_name != "payload" && field_name != "body") {
      ERROR() << "Can't find a field offset for nonexistent field named: " << field_name;
    } else {
      return Size();
    }
  }

  // We have to use a generic lambda to conditionally change iteration direction
  // due to iterator and reverse_iterator being different types.
  auto size_lambda = [&](auto from, auto to) -> Size {
    auto size = Size(0);
    for (auto it = from; it != to; it++) {
      // We've reached the field, end the loop.
      if ((*it)->GetName() == field_name) break;
      const auto& field = *it;
      // If there was a field that wasn't the payload with an unknown size,
      // return an empty Size.
      if (field->GetSize().empty()) {
        return Size();
      }
      size += field->GetSize();
    }
    return size;
  };

  // Change iteration direction based on from_end.
  auto size = Size();
  if (from_end)
    size = size_lambda(fields_.rbegin(), fields_.rend());
  else
    size = size_lambda(fields_.begin(), fields_.end());
  if (size.empty()) return Size();

  // We need the offset until a payload or body field.
  if (parent_ != nullptr) {
    auto parent_payload_offset = parent_->GetOffsetForField("payload", from_end);
    if (!parent_payload_offset.empty()) {
      size += parent_payload_offset;
    } else {
      parent_payload_offset = parent_->GetOffsetForField("body", from_end);
      if (!parent_payload_offset.empty()) {
        size += parent_payload_offset;
      } else {
        return Size();
      }
    }
  }

  return size;
}

FieldList ParentDef::GetParamList() const {
  FieldList params;

  std::set<PacketField::Type> param_types = {
      PacketField::Type::SCALAR, PacketField::Type::ENUM, PacketField::Type::ARRAY,
      PacketField::Type::CUSTOM, PacketField::Type::BODY, PacketField::Type::PAYLOAD,
  };

  if (parent_ != nullptr) {
    auto parent_params = parent_->GetParamList().GetFieldsWithTypes(param_types);

    // Do not include constrained fields in the params
    for (const auto& field : parent_params) {
      if (parent_constraints_.find(field->GetName()) == parent_constraints_.end()) {
        params.AppendField(field);
      }
    }
  }
  // Add our parameters.
  return params.Merge(fields_.GetFieldsWithTypes(param_types));
}

void ParentDef::GenMembers(std::ostream& s) const {
  // Add the parameter list.
  for (int i = 0; i < fields_.size(); i++) {
    if (fields_[i]->GenBuilderParameter(s)) {
      s << "_;";
    }
  }
}
