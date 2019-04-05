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

#include "fields/group_field.h"

GroupField::GroupField(ParseLocation loc, std::list<PacketField*>* fields)
    : PacketField(loc, "Groups have no name"), fields_(fields) {}

GroupField::~GroupField() {
  delete fields_;
}

PacketField::Type GroupField::GetFieldType() const {
  return PacketField::Type::GROUP;
}

std::string GroupField::GetName() const {
  ERROR(this) << "GetName should never be called.";
  return "";
}

Size GroupField::GetSize() const {
  ERROR(this) << "GetSize should never be called.";
  return Size();
}

std::string GroupField::GetType() const {
  ERROR(this) << "GetType should never be called.";
  return "";
}

void GroupField::GenGetter(std::ostream&, Size, Size) const {
  ERROR(this) << "GenGetter should never be called.";
}

bool GroupField::GenBuilderParameter(std::ostream&) const {
  ERROR(this) << "GenBuilderParameter should never be called";
  return false;
}

bool GroupField::HasParameterValidator() const {
  ERROR(this) << "HasParameterValidator should never be called";
  return false;
}

void GroupField::GenParameterValidator(std::ostream&) const {
  ERROR(this) << "Not implemented";
}

void GroupField::GenInserter(std::ostream&) const {
  ERROR(this) << "GenInserter should never be called.";
}

void GroupField::GenValidator(std::ostream&) const {
  ERROR(this) << "GenValidator should never be called.";
}

const std::list<PacketField*>* GroupField::GetFields() const {
  return fields_;
}
