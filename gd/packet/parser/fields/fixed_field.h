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

#include <variant>

#include "enum_def.h"
#include "fields/packet_field.h"
#include "parse_location.h"

class FixedField : public PacketField {
 public:
  FixedField(int size, int64_t value, ParseLocation loc);

  FixedField(EnumDef* enum_def, std::string value, ParseLocation loc);

  virtual PacketField::Type GetFieldType() const override;

  virtual Size GetSize() const override;

  virtual std::string GetType() const override;

  virtual void GenGetter(std::ostream& s, Size start_offset, Size end_offset) const override;

  virtual bool GenBuilderParameter(std::ostream&) const override;

  virtual bool HasParameterValidator() const override;

  virtual void GenParameterValidator(std::ostream&) const override;

  virtual void GenInserter(std::ostream& s) const override;

  virtual void GenValidator(std::ostream& s) const override;

 private:
  void GenValue(std::ostream& s) const;

  PacketField::Type type_;
  int size_;
  EnumDef* enum_;
  std::variant<int64_t, std::string> value_;

  static int unique_id_;
};
