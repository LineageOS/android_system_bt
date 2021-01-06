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

PacketDef::PacketDef(std::string name, FieldList fields) : ParentDef(name, fields, nullptr) {}
PacketDef::PacketDef(std::string name, FieldList fields, PacketDef* parent) : ParentDef(name, fields, parent) {}

PacketField* PacketDef::GetNewField(const std::string&, ParseLocation) const {
  return nullptr;  // Packets can't be fields
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
    s << "{ return " << name_ << "View(std::move(parent)); }";
  } else {
    s << "static " << name_ << "View Create(PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian> packet) ";
    s << "{ return " << name_ << "View(std::move(packet)); }";
  }

  GenTestingParserFromBytes(s);

  std::set<std::string> fixed_types = {
      FixedScalarField::kFieldType,
      FixedEnumField::kFieldType,
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

  s << " public:";
  GenParserToString(s);
  s << "\n";

  s << " protected:\n";
  // Constructor from a View
  if (parent_ != nullptr) {
    s << "explicit " << name_ << "View(" << parent_->name_ << "View parent)";
    s << " : " << parent_->name_ << "View(std::move(parent)) { was_validated_ = false; }";
  } else {
    s << "explicit " << name_ << "View(PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian> packet) ";
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

void PacketDef::GenTestingParserFromBytes(std::ostream& s) const {
  s << "\n#if defined(PACKET_FUZZ_TESTING) || defined(PACKET_TESTING) || defined(FUZZ_TARGET)\n";

  s << "static " << name_ << "View FromBytes(std::vector<uint8_t> bytes) {";
  s << "auto vec = std::make_shared<std::vector<uint8_t>>(bytes);";
  s << "return " << name_ << "View::Create(";
  auto ancestor_ptr = parent_;
  size_t parent_parens = 0;
  while (ancestor_ptr != nullptr) {
    s << ancestor_ptr->name_ << "View::Create(";
    parent_parens++;
    ancestor_ptr = ancestor_ptr->parent_;
  }
  s << "PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian>(vec)";
  for (size_t i = 0; i < parent_parens; i++) {
    s << ")";
  }
  s << ");";
  s << "}";

  s << "\n#endif\n";
}

void PacketDef::GenParserDefinitionPybind11(std::ostream& s) const {
  s << "py::class_<" << name_ << "View";
  if (parent_ != nullptr) {
    s << ", " << parent_->name_ << "View";
  } else {
    s << ", PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian>";
  }
  s << ">(m, \"" << name_ << "View\")";
  if (parent_ != nullptr) {
    s << ".def(py::init([](" << parent_->name_ << "View parent) {";
  } else {
    s << ".def(py::init([](PacketView<" << (is_little_endian_ ? "" : "!") << "kLittleEndian> parent) {";
  }
  s << "auto view =" << name_ << "View::Create(std::move(parent));";
  s << "if (!view.IsValid()) { throw std::invalid_argument(\"Bad packet view\"); }";
  s << "return view; }))";

  s << ".def(py::init(&" << name_ << "View::Create))";
  std::set<std::string> protected_field_types = {
      FixedScalarField::kFieldType,
      FixedEnumField::kFieldType,
      SizeField::kFieldType,
      CountField::kFieldType,
  };
  const auto& public_fields = fields_.GetFieldsWithoutTypes(protected_field_types);
  for (const auto& field : public_fields) {
    auto getter_func_name = field->GetGetterFunctionName();
    if (getter_func_name.empty()) {
      continue;
    }
    s << ".def(\"" << getter_func_name << "\", &" << name_ << "View::" << getter_func_name << ")";
  }
  s << ".def(\"IsValid\", &" << name_ << "View::IsValid)";
  s << ";\n";
}

void PacketDef::GenParserFieldGetter(std::ostream& s, const PacketField* field) const {
  // Start field offset
  auto start_field_offset = GetOffsetForField(field->GetName(), false);
  auto end_field_offset = GetOffsetForField(field->GetName(), true);

  if (start_field_offset.empty() && end_field_offset.empty()) {
    ERROR(field) << "Field location for " << field->GetName() << " is ambiguous, "
                 << "no method exists to determine field location from begin() or end().\n";
  }

  field->GenGetter(s, start_field_offset, end_field_offset);
}

TypeDef::Type PacketDef::GetDefinitionType() const {
  return TypeDef::Type::PACKET;
}

void PacketDef::GenValidator(std::ostream& s) const {
  // Get the static offset for all of our fields.
  int bits_size = 0;
  for (const auto& field : fields_) {
    if (field->GetFieldType() != PaddingField::kFieldType) {
      bits_size += field->GetSize().bits();
    }
  }

  // Write the function declaration.
  s << "virtual bool IsValid() " << (parent_ != nullptr ? " override" : "") << " {";
  s << "if (was_validated_) { return true; } ";
  s << "else { was_validated_ = true; was_validated_ = IsValid_(); return was_validated_; }";
  s << "}";

  s << "protected:";
  s << "virtual bool IsValid_() const {";

  // Offset by the parents known size. We know that any dynamic fields can
  // already be called since the parent must have already been validated by
  // this point.
  auto parent_size = Size(0);
  if (parent_ != nullptr) {
    parent_size = parent_->GetSize(true);
  }

  s << "auto it = begin() + (" << parent_size << ") / 8;";

  // Check if you can extract the static fields.
  // At this point you know you can use the size getters without crashing
  // as long as they follow the instruction that size fields cant come before
  // their corrisponding variable length field.
  s << "it += " << ((bits_size + 7) / 8) << " /* Total size of the fixed fields */;";
  s << "if (it > end()) return false;";

  // For any variable length fields, use their size check.
  for (const auto& field : fields_) {
    if (field->GetFieldType() == ChecksumStartField::kFieldType) {
      auto offset = GetOffsetForField(field->GetName(), false);
      if (!offset.empty()) {
        s << "size_t sum_index = (" << offset << ") / 8;";
      } else {
        offset = GetOffsetForField(field->GetName(), true);
        if (offset.empty()) {
          ERROR(field) << "Checksum Start Field offset can not be determined.";
        }
        s << "size_t sum_index = size() - (" << offset << ") / 8;";
      }

      const auto& field_name = ((ChecksumStartField*)field)->GetStartedFieldName();
      const auto& started_field = fields_.GetField(field_name);
      if (started_field == nullptr) {
        ERROR(field) << __func__ << ": Can't find checksum field named " << field_name << "(" << field->GetName()
                     << ")";
      }
      auto end_offset = GetOffsetForField(started_field->GetName(), false);
      if (!end_offset.empty()) {
        s << "size_t end_sum_index = (" << end_offset << ") / 8;";
      } else {
        end_offset = GetOffsetForField(started_field->GetName(), true);
        if (end_offset.empty()) {
          ERROR(started_field) << "Checksum Field end_offset can not be determined.";
        }
        s << "size_t end_sum_index = size() - (" << started_field->GetSize() << " - " << end_offset << ") / 8;";
      }
      if (is_little_endian_) {
        s << "auto checksum_view = GetLittleEndianSubview(sum_index, end_sum_index);";
      } else {
        s << "auto checksum_view = GetBigEndianSubview(sum_index, end_sum_index);";
      }
      s << started_field->GetDataType() << " checksum;";
      s << "checksum.Initialize();";
      s << "for (uint8_t byte : checksum_view) { ";
      s << "checksum.AddByte(byte);}";
      s << "if (checksum.GetChecksum() != (begin() + end_sum_index).extract<"
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
    if (field->GetFieldType() == CustomField::kFieldType) {
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
      const auto& custom_size_var = field->GetName() + "_size";
      s << "const auto& " << custom_size_var << " = " << field_size.dynamic_string();
      s << "(begin() + (" << offset << ") / 8);";

      s << "if (!" << custom_size_var << ".has_value()) { return false; }";
      s << "it += *" << custom_size_var << ";";
      s << "if (it > end()) return false;";
      continue;
    } else {
      s << "it += (" << field_size.dynamic_string() << ") / 8;";
      s << "if (it > end()) return false;";
    }
  }

  // Validate constraints after validating the size
  if (parent_constraints_.size() > 0 && parent_ == nullptr) {
    ERROR() << "Can't have a constraint on a NULL parent";
  }

  for (const auto& constraint : parent_constraints_) {
    s << "if (Get" << util::UnderscoreToCamelCase(constraint.first) << "() != ";
    const auto& field = parent_->GetParamList().GetField(constraint.first);
    if (field->GetFieldType() == ScalarField::kFieldType) {
      s << std::get<int64_t>(constraint.second);
    } else {
      s << std::get<std::string>(constraint.second);
    }
    s << ") return false;";
  }

  // Validate the packets fields last
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

void PacketDef::GenParserToString(std::ostream& s) const {
  s << "virtual std::string ToString() " << (parent_ != nullptr ? " override" : "") << " {";
  s << "std::stringstream ss;";
  s << "ss << std::showbase << std::hex << \"" << name_ << " { \";";

  if (fields_.size() > 0) {
    s << "ss << \"\" ";
    bool firstfield = true;
    for (const auto& field : fields_) {
      if (field->GetFieldType() == ReservedField::kFieldType || field->GetFieldType() == FixedScalarField::kFieldType ||
          field->GetFieldType() == ChecksumStartField::kFieldType)
        continue;

      s << (firstfield ? " << \"" : " << \", ") << field->GetName() << " = \" << ";

      field->GenStringRepresentation(s, field->GetGetterFunctionName() + "()");

      if (firstfield) {
        firstfield = false;
      }
    }
    s << ";";
  }

  s << "ss << \" }\";";
  s << "return ss.str();";
  s << "}\n";
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
  s << "  virtual ~" << name_ << "Builder() = default;";

  if (!fields_.HasBody()) {
    GenBuilderCreate(s);
    s << "\n";

    GenTestingFromView(s);
    s << "\n";
  }

  GenSerialize(s);
  s << "\n";

  GenSize(s);
  s << "\n";

  s << " protected:\n";
  GenBuilderConstructor(s);
  s << "\n";

  GenBuilderParameterChecker(s);
  s << "\n";

  GenMembers(s);
  s << "};\n";

  GenTestDefine(s);
  s << "\n";

  GenFuzzTestDefine(s);
  s << "\n";
}

void PacketDef::GenTestingFromView(std::ostream& s) const {
  s << "#if defined(PACKET_FUZZ_TESTING) || defined(PACKET_TESTING) || defined(FUZZ_TARGET)\n";

  s << "static std::unique_ptr<" << name_ << "Builder> FromView(" << name_ << "View view) {";
  s << "return " << name_ << "Builder::Create(";
  FieldList params = GetParamList().GetFieldsWithoutTypes({
      BodyField::kFieldType,
  });
  for (int i = 0; i < params.size(); i++) {
    params[i]->GenBuilderParameterFromView(s);
    if (i != params.size() - 1) {
      s << ", ";
    }
  }
  s << ");";
  s << "}";

  s << "\n#endif\n";
}

void PacketDef::GenBuilderDefinitionPybind11(std::ostream& s) const {
  s << "py::class_<" << name_ << "Builder";
  if (parent_ != nullptr) {
    s << ", " << parent_->name_ << "Builder";
  } else {
    if (is_little_endian_) {
      s << ", PacketBuilder<kLittleEndian>";
    } else {
      s << ", PacketBuilder<!kLittleEndian>";
    }
  }
  s << ", std::shared_ptr<" << name_ << "Builder>";
  s << ">(m, \"" << name_ << "Builder\")";
  if (!fields_.HasBody()) {
    GenBuilderCreatePybind11(s);
  }
  s << ".def(\"Serialize\", [](" << name_ << "Builder& builder){";
  s << "std::vector<uint8_t> bytes;";
  s << "BitInserter bi(bytes);";
  s << "builder.Serialize(bi);";
  s << "return bytes;})";
  s << ";\n";
}

void PacketDef::GenTestDefine(std::ostream& s) const {
  s << "#ifdef PACKET_TESTING\n";
  s << "#define DEFINE_AND_INSTANTIATE_" << name_ << "ReflectionTest(...)";
  s << "class " << name_ << "ReflectionTest : public testing::TestWithParam<std::vector<uint8_t>> { ";
  s << "public: ";
  s << "void CompareBytes(std::vector<uint8_t> captured_packet) {";
  s << name_ << "View view = " << name_ << "View::FromBytes(captured_packet);";
  s << "if (!view.IsValid()) { LOG_INFO(\"Invalid Packet Bytes (size = %zu)\", view.size());";
  s << "for (size_t i = 0; i < view.size(); i++) { LOG_INFO(\"%5zd:%02X\", i, *(view.begin() + i)); }}";
  s << "ASSERT_TRUE(view.IsValid());";
  s << "auto packet = " << name_ << "Builder::FromView(view);";
  s << "std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();";
  s << "packet_bytes->reserve(packet->size());";
  s << "BitInserter it(*packet_bytes);";
  s << "packet->Serialize(it);";
  s << "ASSERT_EQ(*packet_bytes, captured_packet);";
  s << "}";
  s << "};";
  s << "TEST_P(" << name_ << "ReflectionTest, generatedReflectionTest) {";
  s << "CompareBytes(GetParam());";
  s << "}";
  s << "INSTANTIATE_TEST_SUITE_P(" << name_ << "_reflection, ";
  s << name_ << "ReflectionTest, testing::Values(__VA_ARGS__))";
  s << "\n#endif";
}

void PacketDef::GenFuzzTestDefine(std::ostream& s) const {
  s << "#if defined(PACKET_FUZZ_TESTING) || defined(PACKET_TESTING)\n";
  s << "#define DEFINE_" << name_ << "ReflectionFuzzTest() ";
  s << "void Run" << name_ << "ReflectionFuzzTest(const uint8_t* data, size_t size) {";
  s << "auto vec = std::vector<uint8_t>(data, data + size);";
  s << name_ << "View view = " << name_ << "View::FromBytes(vec);";
  s << "if (!view.IsValid()) { return; }";
  s << "auto packet = " << name_ << "Builder::FromView(view);";
  s << "std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();";
  s << "packet_bytes->reserve(packet->size());";
  s << "BitInserter it(*packet_bytes);";
  s << "packet->Serialize(it);";
  s << "}";
  s << "\n#endif\n";
  s << "#ifdef PACKET_FUZZ_TESTING\n";
  s << "#define DEFINE_AND_REGISTER_" << name_ << "ReflectionFuzzTest(REGISTRY) ";
  s << "DEFINE_" << name_ << "ReflectionFuzzTest();";
  s << " class " << name_ << "ReflectionFuzzTestRegistrant {";
  s << "public: ";
  s << "explicit " << name_
    << "ReflectionFuzzTestRegistrant(std::vector<void(*)(const uint8_t*, size_t)>& fuzz_test_registry) {";
  s << "fuzz_test_registry.push_back(Run" << name_ << "ReflectionFuzzTest);";
  s << "}}; ";
  s << name_ << "ReflectionFuzzTestRegistrant " << name_ << "_reflection_fuzz_test_registrant(REGISTRY);";
  s << "\n#endif";
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
      PayloadField::kFieldType,
      BodyField::kFieldType,
  });
  // Add the parameters.
  for (int i = 0; i < params.size(); i++) {
    if (params[i]->BuilderParameterMustBeMoved()) {
      s << "std::move(" << params[i]->GetName() << ")";
    } else {
      s << params[i]->GetName();
    }
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

void PacketDef::GenBuilderCreatePybind11(std::ostream& s) const {
  s << ".def(py::init([](";
  auto params = GetParamList();
  std::vector<std::string> constructor_args;
  int i = 1;
  for (const auto& param : params) {
    i++;
    std::stringstream ss;
    auto param_type = param->GetBuilderParameterType();
    if (param_type.empty()) {
      continue;
    }
    // Use shared_ptr instead of unique_ptr for the Python interface
    if (param->BuilderParameterMustBeMoved()) {
      param_type = util::StringFindAndReplaceAll(param_type, "unique_ptr", "shared_ptr");
    }
    ss << param_type << " " << param->GetName();
    constructor_args.push_back(ss.str());
  }
  s << util::StringJoin(",", constructor_args) << "){";

  // Deal with move only args
  for (const auto& param : params) {
    std::stringstream ss;
    auto param_type = param->GetBuilderParameterType();
    if (param_type.empty()) {
      continue;
    }
    if (!param->BuilderParameterMustBeMoved()) {
      continue;
    }
    auto move_only_param_name = param->GetName() + "_move_only";
    s << param_type << " " << move_only_param_name << ";";
    if (param->IsContainerField()) {
      // Assume single layer container and copy it
      auto struct_type = param->GetElementField()->GetDataType();
      struct_type = util::StringFindAndReplaceAll(struct_type, "std::unique_ptr<", "");
      struct_type = util::StringFindAndReplaceAll(struct_type, ">", "");
      s << "for (size_t i = 0; i < " << param->GetName() << ".size(); i++) {";
      // Serialize each struct
      s << "auto " << param->GetName() + "_bytes = std::make_shared<std::vector<uint8_t>>();";
      s << param->GetName() + "_bytes->reserve(" << param->GetName() << "[i]->size());";
      s << "BitInserter " << param->GetName() + "_bi(*" << param->GetName() << "_bytes);";
      s << param->GetName() << "[i]->Serialize(" << param->GetName() << "_bi);";
      // Parse it again
      s << "auto " << param->GetName() << "_view = PacketView<kLittleEndian>(" << param->GetName() << "_bytes);";
      s << param->GetElementField()->GetDataType() << " " << param->GetName() << "_reparsed = ";
      s << "Parse" << struct_type << "(" << param->GetName() + "_view.begin());";
      // Push it into a new container
      if (param->GetFieldType() == VectorField::kFieldType) {
        s << move_only_param_name << ".push_back(std::move(" << param->GetName() + "_reparsed));";
      } else if (param->GetFieldType() == ArrayField::kFieldType) {
        s << move_only_param_name << "[i] = std::move(" << param->GetName() << "_reparsed);";
      } else {
        ERROR() << param << " is not supported by Pybind11";
      }
      s << "}";
    } else {
      // Serialize the parameter and pass the bytes in a RawBuilder
      s << "std::vector<uint8_t> " << param->GetName() + "_bytes;";
      s << param->GetName() + "_bytes.reserve(" << param->GetName() << "->size());";
      s << "BitInserter " << param->GetName() + "_bi(" << param->GetName() << "_bytes);";
      s << param->GetName() << "->Serialize(" << param->GetName() + "_bi);";
      s << move_only_param_name << " = ";
      s << "std::make_unique<RawBuilder>(" << param->GetName() << "_bytes);";
    }
  }
  s << "return " << name_ << "Builder::Create(";
  std::vector<std::string> builder_vars;
  for (const auto& param : params) {
    std::stringstream ss;
    auto param_type = param->GetBuilderParameterType();
    if (param_type.empty()) {
      continue;
    }
    auto param_name = param->GetName();
    if (param->BuilderParameterMustBeMoved()) {
      ss << "std::move(" << param_name << "_move_only)";
    } else {
      ss << param_name;
    }
    builder_vars.push_back(ss.str());
  }
  s << util::StringJoin(",", builder_vars) << ");}";
  s << "))";
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
  s << "explicit " << name_ << "Builder(";

  // Generate the constructor parameters.
  auto params = GetParamList().GetFieldsWithoutTypes({
      PayloadField::kFieldType,
      BodyField::kFieldType,
  });
  for (int i = 0; i < params.size(); i++) {
    params[i]->GenBuilderParameter(s);
    if (i != params.size() - 1) {
      s << ", ";
    }
  }
  if (params.size() > 0 || parent_constraints_.size() > 0) {
    s << ") :";
  } else {
    s << ")";
  }

  // Get the list of parent params to call the parent constructor with.
  FieldList parent_params;
  if (parent_ != nullptr) {
    // Pass parameters to the parent constructor
    s << parent_->name_ << "Builder(";
    parent_params = parent_->GetParamList().GetFieldsWithoutTypes({
        PayloadField::kFieldType,
        BodyField::kFieldType,
    });

    // Go through all the fields and replace constrained fields with fixed values
    // when calling the parent constructor.
    for (int i = 0; i < parent_params.size(); i++) {
      const auto& field = parent_params[i];
      const auto& constraint = parent_constraints_.find(field->GetName());
      if (constraint != parent_constraints_.end()) {
        if (field->GetFieldType() == ScalarField::kFieldType) {
          s << std::get<int64_t>(constraint->second);
        } else if (field->GetFieldType() == EnumField::kFieldType) {
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
    if (saved_params[i]->BuilderParameterMustBeMoved()) {
      s << saved_param_name << "_(std::move(" << saved_param_name << "))";
    } else {
      s << saved_param_name << "_(" << saved_param_name << ")";
    }
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

void PacketDef::GenRustChildEnums(std::ostream& s) const {
  if (!children_.empty()) {
    s << "#[derive(Debug)] ";
    s << "enum " << name_ << "DataChild {";
    for (const auto& child : children_) {
      if (child->name_.rfind("LeGetVendorCapabilitiesComplete", 0) == 0) {
        continue;
      }
      s << child->name_ << "(Arc<" << child->name_ << "Data>),";
    }
    s << "None,";
    s << "}\n";
    s << "#[derive(Debug)] ";
    s << "pub enum " << name_ << "Child {";
    for (const auto& child : children_) {
      if (child->name_.rfind("LeGetVendorCapabilitiesComplete", 0) == 0) {
        continue;
      }
      s << child->name_ << "(" << child->name_ << "Packet),";
    }
    s << "None,";
    s << "}\n";
  }
}

void PacketDef::GenRustStructDeclarations(std::ostream& s) const {
  s << "#[derive(Debug)] ";
  s << "struct " << name_ << "Data {";

  // Generate struct fields
  GenRustStructFieldNameAndType(s);
  if (!children_.empty()) {
    s << "child: " << name_ << "DataChild,";
  }
  s << "}\n";

  // Generate accessor struct
  s << "#[derive(Debug, Clone)] ";
  s << "pub struct " << name_ << "Packet {";
  auto lineage = GetAncestors();
  lineage.push_back(this);
  for (auto it = lineage.begin(); it != lineage.end(); it++) {
    auto def = *it;
    s << util::CamelCaseToUnderScore(def->name_) << ": Arc<" << def->name_ << "Data>,";
  }
  s << "}\n";

  // Generate builder struct
  s << "#[derive(Debug)] ";
  s << "pub struct " << name_ << "Builder {";
  auto params = GetParamList().GetFieldsWithoutTypes({
      PayloadField::kFieldType,
      BodyField::kFieldType,
  });
  for (auto param : params) {
    s << "pub ";
    param->GenRustNameAndType(s);
    s << ", ";
  }
  s << "}\n";
}

bool PacketDef::GenRustStructFieldNameAndType(std::ostream& s) const {
  auto fields = fields_.GetFieldsWithoutTypes({
      BodyField::kFieldType,
      CountField::kFieldType,
      PaddingField::kFieldType,
      ReservedField::kFieldType,
      SizeField::kFieldType,
      PayloadField::kFieldType,
      FixedScalarField::kFieldType,
  });
  if (fields.size() == 0) {
    return false;
  }
  for (int i = 0; i < fields.size(); i++) {
    fields[i]->GenRustNameAndType(s);
    s << ", ";
  }
  return true;
}

void PacketDef::GenRustStructFieldNames(std::ostream& s) const {
  auto fields = fields_.GetFieldsWithoutTypes({
      BodyField::kFieldType,
      CountField::kFieldType,
      PaddingField::kFieldType,
      ReservedField::kFieldType,
      SizeField::kFieldType,
      PayloadField::kFieldType,
      FixedScalarField::kFieldType,
  });
  for (int i = 0; i < fields.size(); i++) {
    s << fields[i]->GetName();
    s << ", ";
  }
}

void PacketDef::GenRustStructSizeField(std::ostream& s) const {
  int size = 0;
  auto fields = fields_.GetFieldsWithoutTypes({
      BodyField::kFieldType,
      CountField::kFieldType,
      SizeField::kFieldType,
  });
  for (int i = 0; i < fields.size(); i++) {
    size += fields[i]->GetSize().bytes();
  }
  if (fields.size() > 0) {
    s << size;
  }
}

void PacketDef::GenRustStructImpls(std::ostream& s) const {
  s << "impl " << name_ << "Data {";
  s << "fn new(";
  bool fields_exist = GenRustStructFieldNameAndType(s);
  if (!children_.empty()) {
    s << "child: " << name_ << "DataChild,";
  }
  s << ") -> Self { ";

  s << "Self { ";
  GenRustStructFieldNames(s);
  if (!children_.empty()) {
    s << "child";
  }

  s << "}";
  s << "}";

  // parse function
  if (parent_constraints_.empty() && !children_.empty() && parent_ != nullptr) {
      auto constraint = FindConstraintField();
      auto constraint_field = GetParamList().GetField(constraint);
      auto constraint_type = constraint_field->GetRustDataType();
      s << "fn parse(bytes: &[u8], " << constraint << ": " << constraint_type
          << ") -> Result<Self> {";
  } else {
    s << "fn parse(bytes: &[u8]) -> Result<Self> {";
  }
  auto fields = fields_.GetFieldsWithoutTypes({
      BodyField::kFieldType,
      FixedScalarField::kFieldType,
  });

  for (auto const& field : fields) {
    auto start_field_offset = GetOffsetForField(field->GetName(), false);
    auto end_field_offset = GetOffsetForField(field->GetName(), true);

    if (start_field_offset.empty() && end_field_offset.empty()) {
      ERROR(field) << "Field location for " << field->GetName() << " is ambiguous, "
                   << "no method exists to determine field location from begin() or end().\n";
    }

    field->GenRustGetter(s, start_field_offset, end_field_offset);
  }

  auto payload_field = fields_.GetFieldsWithTypes({
    PayloadField::kFieldType,
  });

  Size payload_offset;

  if (payload_field.HasPayload()) {
    payload_offset = GetOffsetForField(payload_field[0]->GetName(), false);
  }

  auto constraint_name = FindConstraintField();
  auto constrained_descendants = FindDescendantsWithConstraint(constraint_name);

  if (!children_.empty()) {
    s << "let child = match " << constraint_name << " {";
  }

  for (const auto& desc : constrained_descendants) {
    if (desc.first->name_.rfind("LeGetVendorCapabilitiesComplete", 0) == 0) {
      continue;
    }
    auto desc_path = FindPathToDescendant(desc.first->name_);
    std::reverse(desc_path.begin(), desc_path.end());
    auto constraint_field = GetParamList().GetField(constraint_name);
    auto constraint_type = constraint_field->GetFieldType();

    if (constraint_type == EnumField::kFieldType) {
      auto type = std::get<std::string>(desc.second);
      auto variant_name = type.substr(type.find("::") + 2, type.length());
      auto enum_type = type.substr(0, type.find("::"));
      auto enum_variant = enum_type + "::"
          + util::UnderscoreToCamelCase(util::ToLowerCase(variant_name));
      s << enum_variant;
      s << " => {";
      s << name_ << "DataChild::";
      s << desc_path[0]->name_ << "(Arc::new(";
      if (desc_path[0]->parent_constraints_.empty()) {
        s << desc_path[0]->name_ << "Data::parse(&bytes[" << payload_offset.bytes() << "..]";
        s << ", " << enum_variant << ")?))";
      } else {
        s << desc_path[0]->name_ << "Data::parse(&bytes[" << payload_offset.bytes() << "..])?))";
      }
    } else if (constraint_type == ScalarField::kFieldType) {
      s << std::get<int64_t>(desc.second) << " => {";
      s << "unimplemented!();";
    }
    s << "}\n";
  }

  if (!constrained_descendants.empty()) {
    s << "_ => panic!(\"unexpected value " << "\"),";
  }

  if (!children_.empty()) {
    s << "};\n";
  }

  s << "Ok(Self {";
  fields = fields_.GetFieldsWithoutTypes({
      BodyField::kFieldType,
      CountField::kFieldType,
      PaddingField::kFieldType,
      ReservedField::kFieldType,
      SizeField::kFieldType,
      PayloadField::kFieldType,
      FixedScalarField::kFieldType,
  });

  if (fields_exist) {
    for (int i = 0; i < fields.size(); i++) {
      auto field_type = fields[i]->GetFieldType();
      s << fields[i]->GetName();
      s << ", ";
    }
  }

  if (!children_.empty()) {
    s << "child,";
  }
  s << "})\n";
  s << "}\n";

  // write_to function
  s << "fn write_to(&self, buffer: &mut BytesMut) {";
  if (fields_exist) {
    s << " buffer.resize(buffer.len() + self.get_size(), 0);";
  }

  fields = fields_.GetFieldsWithoutTypes({
      BodyField::kFieldType,
      CountField::kFieldType,
      PaddingField::kFieldType,
      ReservedField::kFieldType,
      SizeField::kFieldType,
      FixedScalarField::kFieldType,
  });

  for (auto const& field : fields) {
    auto start_field_offset = GetOffsetForField(field->GetName(), false);
    auto end_field_offset = GetOffsetForField(field->GetName(), true);

    if (start_field_offset.empty() && end_field_offset.empty()) {
      ERROR(field) << "Field location for " << field->GetName() << " is ambiguous, "
                   << "no method exists to determine field location from begin() or end().\n";
    }

    field->GenRustWriter(s, start_field_offset, end_field_offset);
  }

  if (!children_.empty()) {
    s << "match &self.child {";
    for (const auto& child : children_) {
      if (child->name_.rfind("LeGetVendorCapabilitiesComplete", 0) == 0) {
        continue;
      }
      s << name_ << "DataChild::" << child->name_ << "(value) => value.write_to(buffer),";
    }
    s << name_ << "DataChild::None => {}";
    s << "}";
  }

  s << "}\n";

  if (fields_exist) {
    s << "pub fn get_size(&self) -> usize {";
    GenRustStructSizeField(s);
    s << "}";
  }
  s << "}\n";
}

void PacketDef::GenRustAccessStructImpls(std::ostream& s) const {
  if (complement_ != nullptr && complement_->name_.rfind("LeGetVendorCapabilitiesComplete", 0) != 0) {
    auto complement_root = complement_->GetRootDef();
    auto complement_root_accessor = util::CamelCaseToUnderScore(complement_root->name_);
    s << "impl CommandExpectations for " << name_ << "Packet {";
    s << " type ResponseType = " << complement_->name_ << "Packet;";
    s << " fn _to_response_type(pkt: EventPacket) -> Self::ResponseType { ";
    s << complement_->name_ << "Packet::new(pkt." << complement_root_accessor << ".clone())";
    s << " }";
    s << "}";
  }

  s << "impl " << name_ << "Packet {";
  if (parent_ == nullptr) {
    s << "pub fn parse(bytes: &[u8]) -> Result<Self> { ";
    s << "Ok(Self::new(Arc::new(" << name_ << "Data::parse(bytes)?)))";
    s << "}";
  }
  auto root = GetRootDef();
  auto root_accessor = util::CamelCaseToUnderScore(root->name_);

  s << "pub fn to_bytes(self) -> Bytes {";
  s << " let mut buffer = BytesMut::new();";
  s << " self." << root_accessor << ".write_to(&mut buffer);";
  s << " buffer.freeze()";
  s << "}\n";

  s << "pub fn to_vec(self) -> Vec<u8> { self.to_bytes().to_vec() }\n";

  if (!children_.empty()) {
    s << " pub fn specialize(&self) -> " << name_ << "Child {";
    s << " match &self." << util::CamelCaseToUnderScore(name_) << ".child {";
    for (const auto& child : children_) {
      if (child->name_.rfind("LeGetVendorCapabilitiesComplete", 0) == 0) {
        continue;
      }
      s << name_ << "DataChild::" << child->name_ << "(_) => " << name_ << "Child::" << child->name_ << "("
        << child->name_ << "Packet::new(self." << root_accessor << ".clone())),";
    }
    s << name_ << "DataChild::None => " << name_ << "Child::None,";
    s << "}}";
  }
  auto lineage = GetAncestors();
  lineage.push_back(this);
  const ParentDef* prev = nullptr;

  s << " fn new(root: Arc<" << root->name_ << "Data>) -> Self {";
  for (auto it = lineage.begin(); it != lineage.end(); it++) {
    auto def = *it;
    auto accessor_name = util::CamelCaseToUnderScore(def->name_);
    if (prev == nullptr) {
      s << "let " << accessor_name << " = root;";
    } else {
      s << "let " << accessor_name << " = match &" << util::CamelCaseToUnderScore(prev->name_) << ".child {";
      s << prev->name_ << "DataChild::" << def->name_ << "(value) => (*value).clone(),";
      s << "_ => panic!(\"inconsistent state - child was not " << def->name_ << "\"),";
      s << "};";
    }
    prev = def;
  }
  s << "Self {";
  for (auto it = lineage.begin(); it != lineage.end(); it++) {
    auto def = *it;
    s << util::CamelCaseToUnderScore(def->name_) << ",";
  }
  s << "}}";

  for (auto it = lineage.begin(); it != lineage.end(); it++) {
    auto def = *it;
    auto fields = def->fields_.GetFieldsWithoutTypes({
        BodyField::kFieldType,
        CountField::kFieldType,
        PaddingField::kFieldType,
        ReservedField::kFieldType,
        SizeField::kFieldType,
        PayloadField::kFieldType,
        FixedScalarField::kFieldType,
    });

    for (auto const& field : fields) {
      if (field->GetterIsByRef()) {
        s << "pub fn get_" << field->GetName() << "(&self) -> &" << field->GetRustDataType() << "{";
        s << " &self." << util::CamelCaseToUnderScore(def->name_) << ".as_ref()." << field->GetName();
        s << "}\n";
      } else {
        s << "pub fn get_" << field->GetName() << "(&self) -> " << field->GetRustDataType() << "{";
        s << " self." << util::CamelCaseToUnderScore(def->name_) << ".as_ref()." << field->GetName();
        s << "}\n";
      }
    }
  }

  s << "}\n";

  lineage = GetAncestors();
  for (auto it = lineage.begin(); it != lineage.end(); it++) {
    auto def = *it;
    s << "impl Into<" << def->name_ << "Packet> for " << name_ << "Packet {";
    s << " fn into(self) -> " << def->name_ << "Packet {";
    s << def->name_ << "Packet::new(self." << util::CamelCaseToUnderScore(root->name_) << ")";
    s << " }";
    s << "}\n";
  }
}

void PacketDef::GenRustBuilderStructImpls(std::ostream& s) const {
  if (complement_ != nullptr && complement_->name_.rfind("LeGetVendorCapabilitiesComplete", 0) != 0) {
    auto complement_root = complement_->GetRootDef();
    auto complement_root_accessor = util::CamelCaseToUnderScore(complement_root->name_);
    s << "impl CommandExpectations for " << name_ << "Builder {";
    s << " type ResponseType = " << complement_->name_ << "Packet;";
    s << " fn _to_response_type(pkt: EventPacket) -> Self::ResponseType { ";
    s << complement_->name_ << "Packet::new(pkt." << complement_root_accessor << ".clone())";
    s << " }";
    s << "}";
  }

  s << "impl " << name_ << "Builder {";
  s << "pub fn build(self) -> " << name_ << "Packet {";
  auto lineage = GetAncestors();
  lineage.push_back(this);
  std::reverse(lineage.begin(), lineage.end());

  auto all_constraints = GetAllConstraints();

  const ParentDef* prev = nullptr;
  for (auto ancestor : lineage) {
    auto fields = ancestor->fields_.GetFieldsWithoutTypes({
        BodyField::kFieldType,
        CountField::kFieldType,
        PaddingField::kFieldType,
        ReservedField::kFieldType,
        SizeField::kFieldType,
        PayloadField::kFieldType,
        FixedScalarField::kFieldType,
    });

    auto accessor_name = util::CamelCaseToUnderScore(ancestor->name_);
    s << "let " << accessor_name << "= Arc::new(" << ancestor->name_ << "Data {";
    for (auto field : fields) {
      auto constraint = all_constraints.find(field->GetName());
      s << field->GetName() << ": ";
      if (constraint != all_constraints.end()) {
        if (field->GetFieldType() == ScalarField::kFieldType) {
          s << std::get<int64_t>(constraint->second);
        } else if (field->GetFieldType() == EnumField::kFieldType) {
          auto value = std::get<std::string>(constraint->second);
          auto constant = value.substr(value.find("::") + 2, std::string::npos);
          s << field->GetDataType() << "::" << util::ConstantCaseToCamelCase(constant);
          ;
        } else {
          ERROR(field) << "Constraints on non enum/scalar fields should be impossible.";
        }
      } else {
        s << "self." << field->GetName();
      }
      s << ", ";
    }
    if (!ancestor->children_.empty()) {
      if (prev == nullptr) {
        s << "child: " << name_ << "DataChild::None,";
      } else {
        s << "child: " << ancestor->name_ << "DataChild::" << prev->name_ << "("
          << util::CamelCaseToUnderScore(prev->name_) << "),";
      }
    }
    s << "});";
    prev = ancestor;
  }

  s << name_ << "Packet::new(" << util::CamelCaseToUnderScore(prev->name_) << ")";
  s << "}\n";

  s << "}\n";
  lineage = GetAncestors();
  for (auto it = lineage.begin(); it != lineage.end(); it++) {
    auto def = *it;
    s << "impl Into<" << def->name_ << "Packet> for " << name_ << "Builder {";
    s << " fn into(self) -> " << def->name_ << "Packet { self.build().into() }";
    s << "}\n";
  }
}

void PacketDef::GenRustDef(std::ostream& s) const {
  GenRustChildEnums(s);
  GenRustStructDeclarations(s);
  GenRustStructImpls(s);
  GenRustAccessStructImpls(s);
  GenRustBuilderStructImpls(s);
}
