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

#include "shim/dumpsys.h"

#include <algorithm>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "bundler_generated.h"
#include "dumpsys_generated.h"
#include "dumpsys_module_schema_data.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/reflection_generated.h"
#include "module.h"
#include "os/handler.h"
#include "os/log.h"

namespace bluetooth {
namespace shim {

namespace {
constexpr char kModuleName[] = "shim::Dumpsys";
constexpr char kDumpsysTitle[] = "----- Gd Dumpsys ------";
}  // namespace

constexpr char kArgumentDeveloper[] = "--dev";

class ParsedDumpsysArgs {
 public:
  ParsedDumpsysArgs(const char** args) {
    if (args == nullptr) return;
    const char* p = *args;
    while (p != nullptr) {
      num_args_++;
      if (!strcmp(p, kArgumentDeveloper)) {
        dev_arg_ = true;
      } else {
        // silently ignore unexpected option
      }
      if (++args == nullptr) break;
      p = *args;
    }
  }
  bool IsDeveloper() const {
    return dev_arg_;
  }

 private:
  unsigned num_args_{0};
  bool dev_arg_{false};
};

struct Dumpsys::impl {
 public:
  void DumpWithArgs(int fd, const char** args, std::promise<void> promise);

  impl(const Dumpsys& dumpsys_module, const std::string& bundled_schema_data);
  ~impl() = default;

  int GetNumberOfBundledSchemas() const;

 protected:
  void FilterAsUser(std::string* dumpsys_data);
  void FilterAsDeveloper(std::string* dumpsys_data);
  std::string PrintAsJson(std::string* dumpsys_data) const;

 private:
  const reflection::Schema* FindInBundledSchema(const std::string& name) const;
  const dumpsys::BundledSchema* GetBundledSchema() const;
  const Dumpsys& dumpsys_module_;
  const std::string pre_bundled_schema_;
};

const ModuleFactory Dumpsys::Factory =
    ModuleFactory([]() { return new Dumpsys(bluetooth::dumpsys::GetBundledSchemaData()); });

Dumpsys::impl::impl(const Dumpsys& dumpsys_module, const std::string& pre_bundled_schema)
    : dumpsys_module_(dumpsys_module), pre_bundled_schema_(pre_bundled_schema) {}

int Dumpsys::impl::GetNumberOfBundledSchemas() const {
  return GetBundledSchema()->map()->size();
}

const dumpsys::BundledSchema* Dumpsys::impl::GetBundledSchema() const {
  const dumpsys::BundledSchema* bundled_schema =
      flatbuffers::GetRoot<dumpsys::BundledSchema>(pre_bundled_schema_.data());
  ASSERT(bundled_schema != nullptr);
  return bundled_schema;
}

const reflection::Schema* Dumpsys::impl::FindInBundledSchema(const std::string& name) const {
  const flatbuffers::Vector<flatbuffers::Offset<dumpsys::BundledSchemaMap>>* map = GetBundledSchema()->map();

  for (auto it = map->cbegin(); it != map->cend(); ++it) {
    if (it->name()->str() == name) {
      flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(it->data()->Data()), it->data()->size());
      if (!reflection::VerifySchemaBuffer(verifier)) {
        LOG_WARN("Unable to verify schema buffer name:%s", name.c_str());
        return nullptr;
      }
      return reflection::GetSchema(it->data()->Data());
    }
  }

  LOG_WARN("Unable to find bundled schema name:%s", name.c_str());
  LOG_WARN("  title:%s root_name:%s", GetBundledSchema()->title()->c_str(), GetBundledSchema()->root_name()->c_str());
  for (auto it = map->cbegin(); it != map->cend(); ++it) {
    LOG_WARN("    schema:%s", it->name()->c_str());
  }
  return nullptr;
}

void Dumpsys::impl::FilterAsDeveloper(std::string* dumpsys_data) {
  ASSERT(dumpsys_data != nullptr);
  LOG_INFO("%s UNIMPLEMENTED", __func__);
}

void Dumpsys::impl::FilterAsUser(std::string* dumpsys_data) {
  ASSERT(dumpsys_data != nullptr);
  LOG_INFO("%s UNIMPLEMENTED", __func__);
}

std::string Dumpsys::impl::PrintAsJson(std::string* dumpsys_data) const {
  ASSERT(dumpsys_data != nullptr);

  const flatbuffers::String* root_name = GetBundledSchema()->root_name();
  if (root_name == nullptr) {
    char buf[255];
    snprintf(buf, sizeof(buf), "ERROR: Unable to find root name in prebundled schema\n");
    return std::string(buf);
  }

  const reflection::Schema* schema = FindInBundledSchema(root_name->str());
  if (schema == nullptr) {
    char buf[255];
    snprintf(buf, sizeof(buf), "ERROR: Unable to find schema root name:%s\n", root_name->c_str());
    return std::string(buf);
  }
  return std::string("UNIMPLEMENTED\n");
}

void Dumpsys::impl::DumpWithArgs(int fd, const char** args, std::promise<void> promise) {
  ParsedDumpsysArgs parsed_dumpsys_args(args);
  const auto registry = dumpsys_module_.GetModuleRegistry();

  ModuleDumper dumper(*registry, kDumpsysTitle);
  std::string dumpsys_data;
  dumper.DumpState(&dumpsys_data);

  if (parsed_dumpsys_args.IsDeveloper()) {
    dprintf(fd, " ----- Filtering as Developer -----\n");
    FilterAsDeveloper(&dumpsys_data);
  } else {
    dprintf(fd, " ----- Filtering as User -----\n");
    FilterAsUser(&dumpsys_data);
  }

  dprintf(fd, "%s", PrintAsJson(&dumpsys_data).c_str());
  promise.set_value();
}

Dumpsys::Dumpsys(const std::string& pre_bundled_schema) : pre_bundled_schema_(pre_bundled_schema) {}

void Dumpsys::Dump(int fd, const char** args) {
  std::promise<void> promise;
  auto future = promise.get_future();
  CallOn(pimpl_.get(), &Dumpsys::impl::DumpWithArgs, fd, args, std::move(promise));
  future.get();
}

os::Handler* Dumpsys::GetGdShimHandler() {
  return GetHandler();
}

/**
 * Module methods
 */
void Dumpsys::ListDependencies(ModuleList* list) {}

void Dumpsys::Start() {
  pimpl_ = std::make_unique<impl>(*this, pre_bundled_schema_);
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
