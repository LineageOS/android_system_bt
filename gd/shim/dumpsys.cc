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

  void RegisterDumpsysFunction(const void* token, DumpsysFunction func);  // OBSOLETE
  void UnregisterDumpsysFunction(const void* token);                      // OBSOLETE

  impl(const Dumpsys& dumpsys_module);
  ~impl() = default;

 protected:
  void FilterAsUser(std::string* output);
  void FilterAsDeveloper(std::string* output);
  std::string PrintAsJson(std::string* output) const;

 private:
  std::unordered_map<const void*, DumpsysFunction> dumpsys_functions_;  // OBSOLETE
  const reflection::Schema* FindBundledSchema(
      const dumpsys::BundleSchema& bundle_schema, const std::string& name) const;
  const Dumpsys& dumpsys_module_;
};

const ModuleFactory Dumpsys::Factory = ModuleFactory([]() { return new Dumpsys(); });

Dumpsys::impl::impl(const Dumpsys& dumpsys_module) : dumpsys_module_(dumpsys_module) {}

void Dumpsys::impl::FilterAsDeveloper(std::string* output) {
  ASSERT(output != nullptr);
  LOG_INFO("%s UNIMPLEMENTED", __func__);
}

void Dumpsys::impl::FilterAsUser(std::string* output) {
  ASSERT(output != nullptr);
  LOG_INFO("%s UNIMPLEMENTED", __func__);
}

const reflection::Schema* Dumpsys::impl::FindBundledSchema(
    const dumpsys::BundleSchema& bundle_schema, const std::string& name) const {
  // TODO(cmanton) Return proper schema given schema container and name to index
  return nullptr;
}

std::string Dumpsys::impl::PrintAsJson(std::string* output) const {
  return std::string("UNIMPLEMENTED");
}

void Dumpsys::impl::DumpWithArgs(int fd, const char** args, std::promise<void> promise) {
  ParsedDumpsysArgs parsed_dumpsys_args(args);
  const auto registry = dumpsys_module_.GetModuleRegistry();

  ModuleDumper dumper(*registry, kDumpsysTitle);
  std::string output;
  // Get the dumpstate into out string
  dumper.DumpState(&output);

  if (parsed_dumpsys_args.IsDeveloper()) {
    FilterAsDeveloper(&output);
  } else {
    FilterAsUser(&output);
  }

  dprintf(fd, "%s", PrintAsJson(&output).c_str());
  promise.set_value();
}

void Dumpsys::impl::RegisterDumpsysFunction(const void* token, DumpsysFunction func) {  // OBSOLETE
  ASSERT(dumpsys_functions_.find(token) == dumpsys_functions_.end());
  dumpsys_functions_[token] = func;
}

void Dumpsys::impl::UnregisterDumpsysFunction(const void* token) {  // OBSOLETE
  ASSERT(dumpsys_functions_.find(token) != dumpsys_functions_.end());
  dumpsys_functions_.erase(token);
}

void Dumpsys::Dump(int fd, const char** args) {
  std::promise<void> promise;
  auto future = promise.get_future();
  CallOn(pimpl_.get(), &Dumpsys::impl::DumpWithArgs, fd, args, std::move(promise));
  future.get();
}

void Dumpsys::RegisterDumpsysFunction(const void* token, DumpsysFunction func) {  // OBSOLETE
  GetHandler()->Post(
      common::BindOnce(&Dumpsys::impl::RegisterDumpsysFunction, common::Unretained(pimpl_.get()), token, func));
}

void Dumpsys::UnregisterDumpsysFunction(const void* token) {  // OBSOLETE
  GetHandler()->Post(
      common::BindOnce(&Dumpsys::impl::UnregisterDumpsysFunction, common::Unretained(pimpl_.get()), token));
}

os::Handler* Dumpsys::GetGdShimHandler() {
  return GetHandler();
}

/**
 * Module methods
 */
void Dumpsys::ListDependencies(ModuleList* list) {}

void Dumpsys::Start() {
  pimpl_ = std::make_unique<impl>(*this);
}

void Dumpsys::Stop() {
  pimpl_.reset();
}

std::string Dumpsys::ToString() const {
  return kModuleName;
}

}  // namespace shim
}  // namespace bluetooth
