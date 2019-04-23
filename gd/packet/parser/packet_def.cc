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

#include "packet_def.h"

#include <list>
#include <set>

#include "fields/all_fields.h"
#include "util.h"

PacketDef::PacketDef(std::string name, FieldList fields) : name_(name), fields_(fields), parent_(nullptr){};
PacketDef::PacketDef(std::string name, FieldList fields, PacketDef* parent)
    : name_(name), fields_(fields), parent_(parent){};

void PacketDef::AddParentConstraint(std::string field_name, std::variant<int64_t, std::string> value) {
  // NOTE: This could end up being very slow if there are a lot of constraints.
  const auto& parent_params = parent_->GetParamList();
  const auto& constrained_field = parent_params.GetField(field_name);
  if (constrained_field == nullptr) {
    ERROR() << "Attempting to constrain field " << field_name << " in parent packet " << parent_->name_
            << ", but no such field exists.";
  }

  if (constrained_field->GetFieldType() == PacketField::Type::SCALAR) {
    if (!std::holds_alternative<int64_t>(value)) {
      ERROR(constrained_field) << "Attemting to constrain a scalar field using an enum value in packet "
                               << parent_->name_ << ".";
    }
  } else if (constrained_field->GetFieldType() == PacketField::Type::ENUM) {
    if (!std::holds_alternative<std::string>(value)) {
      ERROR(constrained_field) << "Attemting to constrain an enum field using an scalar value in packet "
                               << parent_->name_ << ".";
    }
    const auto& enum_def = static_cast<EnumField*>(constrained_field)->GetEnumDef();
    if (!enum_def.HasEntry(std::get<std::string>(value))) {
      ERROR(constrained_field) << "No matching enumeration \"" << std::get<std::string>(value)
                               << "for constraint on enum in parent packet " << parent_->name_ << ".";
    }

    // For enums, we have to qualify the value using the enum type name.
    value = enum_def.GetTypeName() + "::" + std::get<std::string>(value);
  } else {
    ERROR(constrained_field) << "Field in parent packet " << parent_->name_ << " is not viable for constraining.";
  }

  parent_constraints_.insert(std::pair(field_name, value));
}

// Assign all size fields to their corresponding variable length fields.
// Will crash if
//  - there aren't any fields that don't match up to a field.
//  - the size field points to a fixed size field.
//  - if the size field comes after the variable length field.
void PacketDef::AssignSizeFields() {
  for (const auto& field : fields_) {
    DEBUG() << "field name: " << field->GetName();

    if (field->GetFieldType() != PacketField::Type::SIZE && field->GetFieldType() != PacketField::Type::COUNT) {
      continue;
    }

    const SizeField* size_field = nullptr;
    size_field = static_cast<SizeField*>(field);
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

    // If we've reached this point then the field wasn't a variable length field.
    // Check to see if the field is a variable length field
    std::cerr << "Can not use size/count in reference to a fixed size field.\n";
    abort();
  }
}

void PacketDef::SetEndianness(bool is_little_endian) {
  is_little_endian_ = is_little_endian;
}

// Get the size for the packet. You scan specify without_payload in order
// to exclude payload fields as child packets will be overriding it.
Size PacketDef::GetSize(bool without_payload) const {
  auto size = Size();

  for (const auto& field : fields_) {
    if (without_payload && field->GetFieldType() == PacketField::Type::PAYLOAD) {
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
Size PacketDef::GetOffsetForField(std::string field_name, bool from_end) const {
  // Check first if the field exists.
  if (fields_.GetField(field_name) == nullptr) {
    if (field_name != "Payload" && field_name != "Body") {
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

  // For parent packets we need the offset until a payload or body field.
  if (parent_ != nullptr) {
    auto parent_payload_offset = parent_->GetOffsetForField("Payload", from_end);
    if (!parent_payload_offset.empty()) {
      size += parent_payload_offset;
    } else {
      parent_payload_offset = parent_->GetOffsetForField("Body", from_end);
      if (!parent_payload_offset.empty()) {
        size += parent_payload_offset;
      } else {
        return Size();
      }
    }
  }

  return size;
}

void PacketDef::GenParserDefinition(std::ostream& s) const {
  s << "class " << name_ << "View";
  if (parent_ != nullptr) {
    s << " : public " << parent_->name_ << "View {";
  } else {
    s << " : public PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian> {";
  }
  s << " public:";

  // Specialize function
  if (parent_ != nullptr) {
    s << "static " << name_ << "View Create(" << parent_->name_ << "View parent)";
    s << "{ return " << name_ << "View(parent); }";
  } else {
    s << "static " << name_ << "View Create(PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian> packet) ";
    s << "{ return " << name_ << "View(packet); }";
  }

  std::set<PacketField::Type> fixed_types = {
      PacketField::Type::FIXED_SCALAR,
      PacketField::Type::FIXED_ENUM,
  };

  // Print all of the public fields which are all the fields minus the fixed fields.
  const auto& public_fields = fields_.GetFieldsWithoutTypes(fixed_types);
  bool has_fixed_fields = public_fields.size() != fields_.size();
  for (const auto& field : public_fields) {
    GenParserFieldGetter(s, field);
    s << "\n";
  }
  GenValidator(s);
  s << "\n";

  s << " protected:\n";
  // Constructor from a View
  if (parent_ != nullptr) {
    s << name_ << "View(" << parent_->name_ << "View parent)";
    s << " : " << parent_->name_ << "View(parent) { was_validated_ = false; }";
  } else {
    s << name_ << "View(PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian> packet) ";
    s << " : PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian>(packet) { was_validated_ = false;}";
  }

  // Print the private fields which are the fixed fields.
  if (has_fixed_fields) {
    const auto& private_fields = fields_.GetFieldsWithTypes(fixed_types);
    s << " private:\n";
    for (const auto& field : private_fields) {
      GenParserFieldGetter(s, field);
      s << "\n";
    }
  }
  s << "};\n";
}

void PacketDef::GenParserFieldGetter(std::ostream& s, const PacketField* field) const {
  // Start field offset
  auto start_field_offset = GetOffsetForField(field->GetName(), false);
  auto end_field_offset = GetOffsetForField(field->GetName(), true);

  if (start_field_offset.empty() && end_field_offset.empty()) {
    std::cerr << "Field location for " << field->GetName() << " is ambiguous, "
              << "no method exists to determine field location from begin() or end().\n";
    abort();
  }

  field->GenGetter(s, start_field_offset, end_field_offset);
}

void PacketDef::GenSerialize(std::ostream& s) const {
  auto header_fields = fields_.GetFieldsBeforePayloadOrBody();
  auto footer_fields = fields_.GetFieldsAfterPayloadOrBody();

  s << "protected:";
  s << "void SerializeHeader(BitInserter&";
  if (parent_ != nullptr || header_fields.size() != 0) {
    s << " i ";
  }
  s << ") const {";

  if (parent_ != nullptr) {
    s << parent_->name_ << "Builder::SerializeHeader(i);";
  }

  for (const auto& field : header_fields) {
    if (field->GetFieldType() == PacketField::Type::SIZE) {
      const auto& field_name = ((SizeField*)field)->GetSizedFieldName();
      const auto& sized_field = fields_.GetField(field_name);
      if (sized_field == nullptr) {
        ERROR(field) << __func__ << "Can't find sized field named " << field_name;
      }
      if (sized_field->GetFieldType() == PacketField::Type::PAYLOAD) {
        s << "size_t payload_bytes = GetPayloadSize();";
        std::string modifier = ((PayloadField*)sized_field)->size_modifier_;
        if (modifier != "") {
          s << "static_assert((" << modifier << ")%8 == 0, \"Modifiers must be byte-aligned\");";
          s << "payload_bytes = payload_bytes + (" << modifier << ") / 8;";
        }
        s << "ASSERT(payload_bytes < (static_cast<size_t>(1) << " << field->GetSize().bits() << "));";
        s << "insert(static_cast<" << field->GetType() << ">(payload_bytes), i," << field->GetSize().bits() << ");";
      } else {
        ERROR(field) << __func__ << "Unhandled sized field type for " << field_name;
      }
    } else if (field->GetFieldType() == PacketField::Type::CHECKSUM_START) {
      const auto& field_name = ((ChecksumStartField*)field)->GetStartedFieldName();
      const auto& started_field = fields_.GetField(field_name);
      if (started_field == nullptr) {
        ERROR(field) << __func__ << ": Can't find checksum field named " << field_name << "(" << field->GetName()
                     << ")";
      }
      s << "auto shared_checksum_ptr = std::make_shared<" << started_field->GetType() << ">();";
      s << started_field->GetType() << "::Initialize(*shared_checksum_ptr);";
      s << "i.RegisterObserver(packet::ByteObserver(";
      s << "[shared_checksum_ptr](uint8_t byte){" << started_field->GetType()
        << "::AddByte(*shared_checksum_ptr, byte);},";
      s << "[shared_checksum_ptr](){ return static_cast<uint64_t>(" << started_field->GetType()
        << "::GetChecksum(*shared_checksum_ptr));}));";
    } else {
      field->GenInserter(s);
    }
  }
  s << "}\n\n";

  s << "void SerializeFooter(BitInserter&";
  if (parent_ != nullptr || footer_fields.size() != 0) {
    s << " i ";
  }
  s << ") const {";

  for (const auto& field : footer_fields) {
    field->GenInserter(s);
  }
  if (parent_ != nullptr) {
    s << parent_->name_ << "Builder::SerializeFooter(i);";
  }
  s << "}\n\n";

  s << "public:";
  s << "virtual void Serialize(BitInserter& i) const override {";
  s << "SerializeHeader(i);";
  if (fields_.HasPayload()) {
    s << "payload_->Serialize(i);";
  }
  s << "SerializeFooter(i);";

  s << "}\n";
}

void PacketDef::GenBuilderSize(std::ostream& s) const {
  auto header_fields = fields_.GetFieldsBeforePayloadOrBody();
  auto footer_fields = fields_.GetFieldsAfterPayloadOrBody();

  s << "protected:";
  s << "size_t BitsOfHeader() const {";
  s << "return ";

  if (parent_ != nullptr) {
    s << parent_->name_ << "Builder::BitsOfHeader() + ";
  }

  size_t header_bits = 0;
  for (const auto& field : header_fields) {
    header_bits += field->GetSize().bits();
  }
  s << header_bits << ";";

  s << "}\n\n";

  s << "size_t BitsOfFooter() const {";
  s << "return ";
  size_t footer_bits = 0;
  for (const auto& field : footer_fields) {
    footer_bits += field->GetSize().bits();
  }

  if (parent_ != nullptr) {
    s << parent_->name_ << "Builder::BitsOfFooter() + ";
  }
  s << footer_bits << ";";
  s << "}\n\n";

  if (fields_.HasPayload()) {
    s << "size_t GetPayloadSize() const {";
    s << "if (payload_ != nullptr) {return payload_->size();}";
    s << "else { return size() - (BitsOfHeader() + BitsOfFooter()) / 8;}";
    s << ";}\n\n";
  }

  s << "public:";
  s << "virtual size_t size() const override {";
  s << "return (BitsOfHeader() / 8)";
  if (fields_.HasPayload()) {
    s << "+ payload_->size()";
  }
  s << " + (BitsOfFooter() / 8);";
  s << "}\n";
}

void PacketDef::GenValidator(std::ostream& s) const {
  // Get the static offset for all of our fields.
  int bits_size = 0;
  for (const auto& field : fields_) {
    bits_size += field->GetSize().bits();
  }

  // Write the function declaration.
  s << "virtual bool IsValid() " << (parent_ != nullptr ? " override" : "") << " {";
  s << "if (was_validated_) { return true; } ";
  s << "else { was_validated_ = true; was_validated_ = IsValid_(); return was_validated_; }";
  s << "}";

  s << "protected:";
  s << "virtual bool IsValid_() const {";
  if (parent_constraints_.size() > 0 && parent_ == nullptr) {
    ERROR() << "Can't have a constraint on a NULL parent";
  }

  for (const auto& constraint : parent_constraints_) {
    s << "if (Get" << util::UnderscoreToCamelCase(constraint.first) << "() != ";
    const auto& field = parent_->GetParamList().GetField(constraint.first);
    if (field->GetFieldType() == PacketField::Type::SCALAR) {
      s << std::get<int64_t>(constraint.second);
    } else {
      s << std::get<std::string>(constraint.second);
    }
    s << ") return false;";
  }

  // Offset by the parents known size. We know that any dynamic fields can
  // already be called since the parent must have already been validated by
  // this point.
  auto parent_size = Size();
  if (parent_ != nullptr) {
    parent_size = parent_->GetSize(true);
  }

  s << "auto it = begin() + " << parent_size.bytes() << " + (" << parent_size.dynamic_string() << ");";

  // Check if you can extract the static fields.
  // At this point you know you can use the size getters without crashing
  // as long as they follow the instruction that size fields cant come before
  // their corrisponding variable length field.
  s << "it += " << ((bits_size + 7) / 8) << " /* Total size of the fixed fields */;";
  s << "if (it > end()) return false;";

  // For any variable length fields, use their size check.
  for (const auto& field : fields_) {
    if (field->GetFieldType() == PacketField::Type::CHECKSUM_START) {
      auto offset = GetOffsetForField(field->GetName(), false);
      if (!offset.empty()) {
        s << "size_t sum_index = " << offset.bytes() << " + (" << offset.dynamic_string() << ");";
      } else {
        offset = GetOffsetForField(field->GetName(), true);
        if (offset.empty()) {
          ERROR(field) << "Checksum Start Field offset can not be determined.";
        }
        s << "size_t sum_index = size() - " << offset.bytes() << " - (" << offset.dynamic_string() << ");";
      }

      const auto& field_name = ((ChecksumStartField*)field)->GetStartedFieldName();
      const auto& started_field = fields_.GetField(field_name);
      if (started_field == nullptr) {
        ERROR(field) << __func__ << ": Can't find checksum field named " << field_name << "(" << field->GetName()
                     << ")";
      }
      auto end_offset = GetOffsetForField(started_field->GetName(), false);
      if (!end_offset.empty()) {
        s << "size_t end_sum_index = " << end_offset.bytes() << " + (" << end_offset.dynamic_string() << ");";
      } else {
        end_offset = GetOffsetForField(started_field->GetName(), true);
        if (end_offset.empty()) {
          ERROR(started_field) << "Checksum Field end_offset can not be determined.";
        }
        s << "size_t end_sum_index = size() - " << started_field->GetSize().bytes() << " - " << end_offset.bytes()
          << " - (" << end_offset.dynamic_string() << ");";
      }
      if (is_little_endian_) {
        s << "auto checksum_view = GetLittleEndianSubview(sum_index, end_sum_index);";
      } else {
        s << "auto checksum_view = GetBigEndianSubview(sum_index, end_sum_index);";
      }
      s << started_field->GetType() << " checksum;";
      s << started_field->GetType() << "::Initialize(checksum);";
      s << "for (uint8_t byte : checksum_view) { ";
      s << started_field->GetType() << "::AddByte(checksum, byte);}";
      s << "if (" << started_field->GetType() << "::GetChecksum(checksum) != (begin() + end_sum_index).extract<"
        << util::GetTypeForSize(started_field->GetSize().bits()) << ">()) { return false; }";

      continue;
    }

    auto field_size = field->GetSize();
    // Fixed size fields have already been handled.
    if (!field_size.has_dynamic()) {
      continue;
    }

    // Custom fields with dynamic size must have the offset for the field passed in as well
    // as the end iterator so that they may ensure that they don't try to read past the end.
    // Custom fields with fixed sizes will be handled in the static offset checking.
    if (field->GetFieldType() == PacketField::Type::CUSTOM) {
      const auto& custom_size_var = field->GetName() + "_size";

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

      // Custom fields are special as their size field takes an argument.
      s << "const auto& " << custom_size_var << " = " << field_size.dynamic_string();
      s << "(begin() + " << offset.bytes() << " + (" << offset.dynamic_string() << "));";

      s << "if (!" << custom_size_var << ".has_value()) { return false; }";
      s << "it += *" << custom_size_var << ";";
      s << "if (it > end()) return false;";
      continue;
    } else {
      s << "it += " << field_size.dynamic_string() << ";";
      s << "if (it > end()) return false;";
    }
  }

  for (const auto& field : fields_) {
    field->GenValidator(s);
    s << "\n";
  }

  s << "return true;";
  s << "}\n";
  if (parent_ == nullptr) {
    s << "bool was_validated_{false};\n";
  }
}

void PacketDef::GenBuilderDefinition(std::ostream& s) const {
  s << "class " << name_ << "Builder";
  if (parent_ != nullptr) {
    s << " : public " << parent_->name_ << "Builder";
  } else {
    if (is_little_endian_) {
      s << " : public PacketBuilder<kLittleEndian>";
    } else {
      s << " : public PacketBuilder<!kLittleEndian>";
    }
  }
  s << " {";
  s << " public:";
  s << "  virtual ~" << name_ << "Builder()" << (parent_ != nullptr ? " override" : "") << " = default;";

  if (!fields_.HasBody()) {
    GenBuilderCreate(s);
    s << "\n";
  }

  GenSerialize(s);
  s << "\n";

  GenBuilderSize(s);
  s << "\n";

  s << " protected:\n";
  GenBuilderConstructor(s);
  s << "\n";

  GenBuilderParameterChecker(s);
  s << "\n";

  GenBuilderMembers(s);
  s << "};\n";
}

FieldList PacketDef::GetParamList() const {
  FieldList params;

  std::set<PacketField::Type> param_types = {
      PacketField::Type::SCALAR, PacketField::Type::ENUM,    PacketField::Type::CUSTOM,
      PacketField::Type::BODY,   PacketField::Type::PAYLOAD,
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

  // Add the parameters for this packet.
  return params.Merge(fields_.GetFieldsWithTypes(param_types));
}

FieldList PacketDef::GetParametersToValidate() const {
  FieldList params_to_validate;
  for (const auto& field : GetParamList()) {
    if (field->HasParameterValidator()) {
      params_to_validate.AppendField(field);
    }
  }
  return params_to_validate;
}

void PacketDef::GenBuilderCreate(std::ostream& s) const {
  s << "static std::unique_ptr<" << name_ << "Builder> Create(";

  auto params = GetParamList();
  for (int i = 0; i < params.size(); i++) {
    params[i]->GenBuilderParameter(s);
    if (i != params.size() - 1) {
      s << ", ";
    }
  }
  s << ") {";

  // Call the constructor
  s << "auto builder = std::unique_ptr<" << name_ << "Builder>(new " << name_ << "Builder(";

  params = params.GetFieldsWithoutTypes({
      PacketField::Type::PAYLOAD,
      PacketField::Type::BODY,
  });
  // Add the parameters.
  for (int i = 0; i < params.size(); i++) {
    s << params[i]->GetName();
    if (i != params.size() - 1) {
      s << ", ";
    }
  }

  s << "));";
  if (fields_.HasPayload()) {
    s << "builder->payload_ = std::move(payload);";
  }
  s << "return builder;";
  s << "}\n";
}

void PacketDef::GenBuilderParameterChecker(std::ostream& s) const {
  FieldList params_to_validate = GetParametersToValidate();

  // Skip writing this function if there is nothing to validate.
  if (params_to_validate.size() == 0) {
    return;
  }

  // Generate function arguments.
  s << "void CheckParameterValues(";
  for (int i = 0; i < params_to_validate.size(); i++) {
    params_to_validate[i]->GenBuilderParameter(s);
    if (i != params_to_validate.size() - 1) {
      s << ", ";
    }
  }
  s << ") {";

  // Check the parameters.
  for (const auto& field : params_to_validate) {
    field->GenParameterValidator(s);
  }
  s << "}\n";
}

void PacketDef::GenBuilderConstructor(std::ostream& s) const {
  s << name_ << "Builder(";

  // Generate the constructor parameters.
  auto params = GetParamList().GetFieldsWithoutTypes({
      PacketField::Type::PAYLOAD,
      PacketField::Type::BODY,
  });
  for (int i = 0; i < params.size(); i++) {
    params[i]->GenBuilderParameter(s);
    if (i != params.size() - 1) {
      s << ", ";
    }
  }
  s << ") :";

  // Get the list of parent params to call the parent constructor with.
  FieldList parent_params;
  if (parent_ != nullptr) {
    // Pass parameters to the parent constructor
    s << parent_->name_ << "Builder(";
    parent_params = parent_->GetParamList().GetFieldsWithoutTypes({
        PacketField::Type::PAYLOAD,
        PacketField::Type::BODY,
    });

    // Go through all the fields and replace constrained fields with fixed values
    // when calling the parent constructor.
    for (int i = 0; i < parent_params.size(); i++) {
      const auto& field = parent_params[i];
      const auto& constraint = parent_constraints_.find(field->GetName());
      if (constraint != parent_constraints_.end()) {
        if (field->GetFieldType() == PacketField::Type::SCALAR) {
          s << std::get<int64_t>(constraint->second);
        } else if (field->GetFieldType() == PacketField::Type::ENUM) {
          s << std::get<std::string>(constraint->second);
        } else {
          ERROR(field) << "Constraints on non enum/scalar fields should be impossible.";
        }

        s << "/* " << field->GetName() << "_ */";
      } else {
        s << field->GetName();
      }

      if (i != parent_params.size() - 1) {
        s << ", ";
      }
    }
    s << ") ";
  }

  // Build a list of parameters that excludes all parent parameters.
  FieldList saved_params;
  for (const auto& field : params) {
    if (parent_params.GetField(field->GetName()) == nullptr) {
      saved_params.AppendField(field);
    }
  }
  if (parent_ != nullptr && saved_params.size() > 0) {
    s << ",";
  }
  for (int i = 0; i < saved_params.size(); i++) {
    const auto& saved_param_name = saved_params[i]->GetName();
    s << saved_param_name << "_(" << saved_param_name << ")";
    if (i != saved_params.size() - 1) {
      s << ",";
    }
  }
  s << " {";

  FieldList params_to_validate = GetParametersToValidate();

  if (params_to_validate.size() > 0) {
    s << "CheckParameterValues(";
    for (int i = 0; i < params_to_validate.size(); i++) {
      s << params_to_validate[i]->GetName() << "_";
      if (i != params_to_validate.size() - 1) {
        s << ", ";
      }
    }
    s << ");";
  }

  s << "}\n";
}

void PacketDef::GenBuilderMembers(std::ostream& s) const {
  // Add the parameter list.
  for (int i = 0; i < fields_.size(); i++) {
    if (fields_[i]->GenBuilderParameter(s)) {
      s << "_;";
    }
  }
}
