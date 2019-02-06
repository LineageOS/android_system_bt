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

#pragma once

#include <map>
#include <variant>

#include "enum_def.h"
#include "field_list.h"
#include "fields/all_fields.h"
#include "fields/packet_field.h"
#include "parent_def.h"
#include "parse_location.h"

class StructDef : public ParentDef {
 public:
  StructDef(std::string name, FieldList fields);
  StructDef(std::string name, FieldList fields, StructDef* parent);

  PacketField* GetNewField(const std::string& name, ParseLocation loc) const;

  TypeDef::Type GetDefinitionType() const;

  void GenParse(std::ostream& s) const;

  void GenDefinition(std::ostream& s) const;

  void GenConstructor(std::ostream& s) const;
};
