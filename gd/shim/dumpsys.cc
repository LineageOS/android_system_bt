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

#include <algorithm>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/dumpsys.h"

namespace bluetooth {
namespace shim {

namespace {
constexpr char kModuleName[] = "shim::Dumpsys";
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

  void RegisterDumpsysFunction(const void* token, DumpsysFunction func);
  void UnregisterDumpsysFunction(const void* token);

  ~impl() = default;

 private:
  std::unordered_map<const void*, DumpsysFunction> dumpsys_functions_;
};

const ModuleFactory Dumpsys::Factory = ModuleFactory([]() { return new Dumpsys(); });

void Dumpsys::impl::DumpWithArgs(int fd, const char** args, std::promise<void> promise) {
  ParsedDumpsysArgs parsed_dumpsys_args(args);
  if (parsed_dumpsys_args.IsDeveloper()) {
    // TODO(cmanton) Create development Dumper
  } else {
    // TODO(cmanton) Create typical Dumper
  }

  std::for_each(dumpsys_functions_.begin(), dumpsys_functions_.end(),
                [fd](std::pair<const void*, DumpsysFunction> element) { element.second(fd); });
  promise.set_value();
}

void Dumpsys::impl::RegisterDumpsysFunction(const void* token, DumpsysFunction func) {
  ASSERT(dumpsys_functions_.find(token) == dumpsys_functions_.end());
  dumpsys_functions_[token] = func;
}

void Dumpsys::impl::UnregisterDumpsysFunction(const void* token) {
  ASSERT(dumpsys_functions_.find(token) != dumpsys_functions_.end());
  dumpsys_functions_.erase(token);
}

void Dumpsys::Dump(int fd, const char** args) {
  std::promise<void> promise;
  auto future = promise.get_future();
  GetHandler()->BindOnceOn(pimpl_.get(), &Dumpsys::impl::DumpWithArgs, fd, args, std::move(promise));
  future.get();
}

void Dumpsys::RegisterDumpsysFunction(const void* token, DumpsysFunction func) {
  GetHandler()->Post(
      common::BindOnce(&Dumpsys::impl::RegisterDumpsysFunction, common::Unretained(pimpl_.get()), token, func));
}

void Dumpsys::UnregisterDumpsysFunction(const void* token) {
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
  pimpl_ = std::make_unique<impl>();
}

void Dumpsys::Stop() {
  pimpl_.reset();
}

std::string Dumpsys::ToString() const {
  return kModuleName;
}

}  // namespace shim
}  // namespace bluetooth
