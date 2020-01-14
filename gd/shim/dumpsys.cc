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
#include <unordered_map>
#include <utility>

#include "module.h"
#include "os/handler.h"
#include "os/log.h"
#include "shim/dumpsys.h"

namespace bluetooth {
namespace shim {

struct Dumpsys::impl {
 public:
  void Dump(int fd, std::promise<void> promise);
  void Register(const void* token, DumpFunction func);
  void Unregister(const void* token);

  ~impl();

 private:
  std::unordered_map<const void*, DumpFunction> dump_functions_;
};

const ModuleFactory Dumpsys::Factory = ModuleFactory([]() { return new Dumpsys(); });

Dumpsys::impl::~impl() {
  ASSERT(dump_functions_.empty());
}

void Dumpsys::impl::Dump(int fd, std::promise<void> promise) {
  dprintf(fd, "%s Registered submodules:%zd\n", "gd::shim::dumpsys", dump_functions_.size());
  std::for_each(dump_functions_.begin(), dump_functions_.end(),
                [fd](std::pair<const void*, DumpFunction> element) { element.second(fd); });
  promise.set_value();
}

void Dumpsys::impl::Register(const void* token, DumpFunction func) {
  ASSERT(dump_functions_.find(token) == dump_functions_.end());
  dump_functions_[token] = func;
}

void Dumpsys::impl::Unregister(const void* token) {
  ASSERT(dump_functions_.find(token) != dump_functions_.end());
  dump_functions_.erase(token);
}

void Dumpsys::Dump(int fd) {
  std::promise<void> promise;
  auto future = promise.get_future();
  GetHandler()->Post(common::BindOnce(&Dumpsys::impl::Dump, common::Unretained(pimpl_.get()), fd, std::move(promise)));
  future.get();
}

void Dumpsys::Register(const void* token, DumpFunction func) {
  GetHandler()->Post(common::BindOnce(&Dumpsys::impl::Register, common::Unretained(pimpl_.get()), token, func));
}

void Dumpsys::Unregister(const void* token) {
  GetHandler()->Post(common::BindOnce(&Dumpsys::impl::Unregister, common::Unretained(pimpl_.get()), token));
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

}  // namespace shim
}  // namespace bluetooth
