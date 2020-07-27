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
#define LOG_TAG "bt_gd_shim"

#include <future>
#include <string>

#include "dumpsys/filter.h"
#include "generated_dumpsys_bundled_schema.h"
#include "module.h"
#include "os/log.h"
#include "os/system_properties.h"
#include "shim/dumpsys.h"
#include "shim/dumpsys_args.h"

namespace bluetooth {
namespace shim {

static const std::string kReadOnlyDebuggableProperty = "ro.debuggable";

namespace {
constexpr char kModuleName[] = "shim::Dumpsys";
constexpr char kDumpsysTitle[] = "----- Gd Dumpsys ------";
}  // namespace

struct Dumpsys::impl {
 public:
  void DumpWithArgsSync(int fd, const char** args, std::promise<void> promise);
  int GetNumberOfBundledSchemas() const;

  impl(const Dumpsys& dumpsys_module, const dumpsys::ReflectionSchema& reflection_schema);
  ~impl() = default;

 protected:
  void FilterAsUser(std::string* dumpsys_data);
  void FilterAsDeveloper(std::string* dumpsys_data);
  std::string PrintAsJson(std::string* dumpsys_data) const;

  bool IsDebuggable() const;

 private:
  void DumpWithArgsAsync(int fd, const char** args);

  const Dumpsys& dumpsys_module_;
  const dumpsys::ReflectionSchema reflection_schema_;
};

const ModuleFactory Dumpsys::Factory =
    ModuleFactory([]() { return new Dumpsys(bluetooth::dumpsys::GetBundledSchemaData()); });

Dumpsys::impl::impl(const Dumpsys& dumpsys_module, const dumpsys::ReflectionSchema& reflection_schema)
    : dumpsys_module_(dumpsys_module), reflection_schema_(std::move(reflection_schema)) {}

int Dumpsys::impl::GetNumberOfBundledSchemas() const {
  return reflection_schema_.GetNumberOfBundledSchemas();
}

bool Dumpsys::impl::IsDebuggable() const {
  return (os::GetSystemProperty(kReadOnlyDebuggableProperty) == "1");
}

void Dumpsys::impl::FilterAsDeveloper(std::string* dumpsys_data) {
  ASSERT(dumpsys_data != nullptr);
  dumpsys::FilterInPlace(dumpsys::FilterType::AS_DEVELOPER, reflection_schema_, dumpsys_data);
}

void Dumpsys::impl::FilterAsUser(std::string* dumpsys_data) {
  ASSERT(dumpsys_data != nullptr);
  dumpsys::FilterInPlace(dumpsys::FilterType::AS_USER, reflection_schema_, dumpsys_data);
}

std::string Dumpsys::impl::PrintAsJson(std::string* dumpsys_data) const {
  ASSERT(dumpsys_data != nullptr);

  const std::string root_name = reflection_schema_.GetRootName();
  if (root_name.empty()) {
    char buf[255];
    snprintf(buf, sizeof(buf), "ERROR: Unable to find root name in prebundled reflection schema\n");
    LOG_WARN("%s", buf);
    return std::string(buf);
  }

  const reflection::Schema* schema = reflection_schema_.FindInReflectionSchema(root_name);
  if (schema == nullptr) {
    char buf[255];
    snprintf(buf, sizeof(buf), "ERROR: Unable to find schema root name:%s\n", root_name.c_str());
    LOG_WARN("%s", buf);
    return std::string(buf);
  }

  flatbuffers::Parser parser;
  if (!parser.Deserialize(schema)) {
    char buf[255];
    snprintf(buf, sizeof(buf), "ERROR: Unable to deserialize bundle root name:%s\n", root_name.c_str());
    LOG_WARN("%s", buf);
    return std::string(buf);
  }

  std::string jsongen;
  flatbuffers::GenerateText(parser, dumpsys_data->data(), &jsongen);
  return jsongen;
}

void Dumpsys::impl::DumpWithArgsAsync(int fd, const char** args) {
  ParsedDumpsysArgs parsed_dumpsys_args(args);
  const auto registry = dumpsys_module_.GetModuleRegistry();

  ModuleDumper dumper(*registry, kDumpsysTitle);
  std::string dumpsys_data;
  dumper.DumpState(&dumpsys_data);

  if (parsed_dumpsys_args.IsDeveloper() || IsDebuggable()) {
    dprintf(fd, " ----- Filtering as Developer -----\n");
    FilterAsDeveloper(&dumpsys_data);
  } else {
    dprintf(fd, " ----- Filtering as User -----\n");
    FilterAsUser(&dumpsys_data);
  }

  dprintf(fd, "%s", PrintAsJson(&dumpsys_data).c_str());
}

void Dumpsys::impl::DumpWithArgsSync(int fd, const char** args, std::promise<void> promise) {
  DumpWithArgsAsync(fd, args);
  promise.set_value();
}

Dumpsys::Dumpsys(const std::string& pre_bundled_schema)
    : reflection_schema_(dumpsys::ReflectionSchema(pre_bundled_schema)) {}

void Dumpsys::Dump(int fd, const char** args) {
  std::promise<void> promise;
  auto future = promise.get_future();
  CallOn(pimpl_.get(), &Dumpsys::impl::DumpWithArgsSync, fd, args, std::move(promise));
  future.get();
}

void Dumpsys::Dump(int fd, const char** args, std::promise<void> promise) {
  CallOn(pimpl_.get(), &Dumpsys::impl::DumpWithArgsSync, fd, args, std::move(promise));
}

os::Handler* Dumpsys::GetGdShimHandler() {
  return GetHandler();
}

/**
 * Module methods
 */
void Dumpsys::ListDependencies(ModuleList* list) {}

void Dumpsys::Start() {
  pimpl_ = std::make_unique<impl>(*this, reflection_schema_);
}

void Dumpsys::Stop() {
  pimpl_.reset();
}

DumpsysDataFinisher Dumpsys::GetDumpsysData(flatbuffers::FlatBufferBuilder* fb_builder) const {
  auto name = fb_builder->CreateString("----- Shim Dumpsys -----");
  auto example_piecemeal_string = fb_builder->CreateString("Example Piecemeal String");
  auto example_instant_string = fb_builder->CreateString("Example Instant String");

  ExamplePiecemealTableBuilder example_piecemeal_table_builder(*fb_builder);
  example_piecemeal_table_builder.add_example_string(example_piecemeal_string);
  example_piecemeal_table_builder.add_example_int(123);
  example_piecemeal_table_builder.add_example_float(1.23);
  auto example_piecemeal_table = example_piecemeal_table_builder.Finish();

  auto example_instant_table = CreateExampleInstantTable(*fb_builder, example_instant_string, 246, 2.46);

  DumpsysModuleDataBuilder builder(*fb_builder);
  builder.add_title(name);
  builder.add_number_of_bundled_schemas(pimpl_->GetNumberOfBundledSchemas());
  builder.add_example_piecemeal_table(example_piecemeal_table);
  builder.add_example_instant_table(example_instant_table);
  auto dumpsys_data = builder.Finish();

  return [dumpsys_data](DumpsysDataBuilder* builder) { builder->add_shim_dumpsys_data(dumpsys_data); };
}

std::string Dumpsys::ToString() const {
  return kModuleName;
}

}  // namespace shim
}  // namespace bluetooth
