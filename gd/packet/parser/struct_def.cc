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

#include "struct_def.h"

#include "fields/all_fields.h"
#include "util.h"

StructDef::StructDef(std::string name, FieldList fields) : ParentDef(name, fields, nullptr){};
StructDef::StructDef(std::string name, FieldList fields, StructDef* parent) : ParentDef(name, fields, parent){};

PacketField* StructDef::GetNewField(const std::string& name, ParseLocation loc) const {
  Size total_size = GetSize(false);
  if (fields_.HasBody()) {
    ERROR(new StructField(name, name_, -1, loc)) << "Variable size structs are not supported";
    fprintf(stderr, "total_size of %s(%s) = %s\n", name_.c_str(), name.c_str(), total_size.ToString().c_str());
    abort();
    return new StructField(name, name_, -1, loc);
  } else {
    return new StructField(name, name_, total_size.bits(), loc);
  }
}

TypeDef::Type StructDef::GetDefinitionType() const {
  return TypeDef::Type::STRUCT;
}

void StructDef::GenParse(std::ostream& s) const {
  if (is_little_endian_) {
    s << "static Iterator<kLittleEndian> Parse(std::vector<" << name_ << ">& vec, Iterator<kLittleEndian> it) {";
  } else {
    s << "static Iterator<!kLittleEndian> Parse(std::vector<" << name_ << ">& vec, Iterator<!kLittleEndian> it) {";
  }
  s << "auto begin_it = it;";
  s << name_ << " one;";
  if (parent_ != nullptr) {
    s << "begin_it += one." << parent_->name_ << "::BitsOfHeader() / 8;";
  }
  Size field_offset = Size(0);
  for (const auto& field : fields_) {
    // TODO: DON'T commit this logging
    s << "\n/* (before adding) field_offset " << field_offset.bits() << " */\n ";
    s << "\n/* (before adding) field->GetSize() " << field->GetSize().bits() << " */\n ";
    // Size next_field_offset = field_offset + field->GetSize();
    Size next_field_offset = field->GetSize() + field_offset.bits();
    s << "\n/* field_offset " << field_offset.bits() << " */\n ";
    if (field->GetFieldType() != ReservedField::kFieldType && field->GetFieldType() != BodyField::kFieldType &&
        field->GetFieldType() != FixedScalarField::kFieldType && field->GetFieldType() != SizeField::kFieldType &&
        field->GetFieldType() != CountField::kFieldType) {
      s << "{";
      field->GenExtractor(s, field_offset, next_field_offset);
      s << "one." << field->GetName() << "_ = value;";
      s << "}";
    }
    field_offset = next_field_offset;
  }
  s << "vec.push_back(one);";
  s << "return it + " << field_offset.bytes() << ";";
  s << "}";
}

void StructDef::GenDefinition(std::ostream& s) const {
  s << "class " << name_;
  if (parent_ != nullptr) {
    s << " : public " << parent_->name_;
  } else {
    if (is_little_endian_) {
      s << " : public PacketStruct<kLittleEndian>";
    } else {
      s << " : public PacketStruct<!kLittleEndian>";
    }
  }
  s << " {";
  s << " public:";

  GenConstructor(s);

  std::set<std::string> fixed_types = {
      FixedScalarField::kFieldType,
      FixedEnumField::kFieldType,
  };

  // Print all of the public fields which are all the fields minus the fixed fields.
  const auto& public_fields = fields_.GetFieldsWithoutTypes(fixed_types);
  bool has_fixed_fields = public_fields.size() != fields_.size();
  for (const auto& field : public_fields) {
    // GenParserFieldGetter(s, field);
    s << "/*FieldGetter for " << field->GetName() << "*/\n";
    s << "\n";
  }

  // Print the private fields which are the fixed fields.
  if (has_fixed_fields) {
    const auto& private_fields = fields_.GetFieldsWithTypes(fixed_types);
    s << "/* private: */\n";
    for (const auto& field : private_fields) {
      // GenParserFieldGetter(s, field);
      s << "/* FieldGetter for " << field->GetName() << "*/\n";
    }
  }
  s << " public:\n";
  s << "  virtual ~" << name_ << "() override = default;\n";

  GenSerialize(s);
  s << "\n";

  GenParse(s);
  s << "\n";

  GenSize(s);
  s << "\n";

  GenMembers(s);
  s << "};\n";
}

void StructDef::GenConstructor(std::ostream& s) const {
  if (parent_ != nullptr) {
    s << name_ << "() : " << parent_->name_ << "() {";
  } else {
    s << name_ << "() {";
  }

  // Get the list of parent params.
  FieldList parent_params;
  if (parent_ != nullptr) {
    parent_params = parent_->GetParamList().GetFieldsWithoutTypes({
        PayloadField::kFieldType,
        BodyField::kFieldType,
    });

    // Set constrained parent fields to their correct values.
    for (int i = 0; i < parent_params.size(); i++) {
      const auto& field = parent_params[i];
      const auto& constraint = parent_constraints_.find(field->GetName());
      if (constraint != parent_constraints_.end()) {
        s << parent_->name_ << "::" << field->GetName() << "_ = ";
        if (field->GetFieldType() == ScalarField::kFieldType) {
          s << std::get<int64_t>(constraint->second) << ";";
        } else if (field->GetFieldType() == EnumField::kFieldType) {
          s << std::get<std::string>(constraint->second) << ";";
        } else {
          ERROR(field) << "Constraints on non enum/scalar fields should be impossible.";
        }
      }
    }
  }

  /*
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

  */
  s << "}\n";
}
