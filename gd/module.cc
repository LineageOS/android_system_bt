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

#include "module.h"

using ::bluetooth::os::Handler;
using ::bluetooth::os::Thread;

namespace bluetooth {

ModuleFactory::ModuleFactory(std::function<Module*()> ctor) : ctor_(ctor) {
}

Handler* Module::GetHandler() {
  return handler_;
}

bool ModuleRegistry::IsStarted(const ModuleFactory* factory) const {
  return started_modules_.find(factory) != started_modules_.end();
}

void ModuleRegistry::Start(ModuleList* modules, Thread* thread) {
  for (auto it = modules->list_.begin(); it != modules->list_.end(); it++) {
    Start(*it, thread);
  }
}

void ModuleRegistry::Start(const ModuleFactory* module, Thread* thread) {
  if (IsStarted(module)) {
    return;
  }

  Module* instance = module->ctor_();
  instance->handler_ = new Handler(thread);

  ModuleList dependencies;
  instance->ListDependencies(&dependencies);
  Start(&dependencies, thread);

  instance->Start(this);
  start_order_.push_back(module);
  started_modules_[module] = instance;
}

void ModuleRegistry::StopAll() {
  // Since modules were brought up in dependency order,
  // it is safe to tear down by going in reverse order.
  for (auto it = start_order_.rbegin(); it != start_order_.rend(); it++) {
    auto instance = started_modules_.find(*it);
    ASSERT(instance != started_modules_.end());
    instance->second->Stop(this);

    delete instance->second->handler_;
    delete instance->second;
    started_modules_.erase(instance);
  }

  ASSERT(started_modules_.empty());
  start_order_.clear();
}
}  // namespace bluetooth
