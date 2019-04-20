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

#include <iostream>

#include "fields/custom_field.h"
#include "parse_location.h"
#include "type_def.h"

class CustomFieldDef : public TypeDef {
 public:
  CustomFieldDef(std::string name, std::string include, int size);

  virtual PacketField* GetNewField(const std::string& name, ParseLocation loc) const override;

  virtual Type GetDefinitionType() const override;

  virtual void GenInclude(std::ostream& s) const;

  virtual void GenUsing(std::ostream& s) const;

  const std::string include_;
};
