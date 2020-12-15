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
#include "dumpsys/init_flags.h"

using ::bluetooth::os::Handler;
using ::bluetooth::os::Thread;

namespace bluetooth {

constexpr std::chrono::milliseconds kModuleStopTimeout = std::chrono::milliseconds(2000);

ModuleFactory::ModuleFactory(std::function<Module*()> ctor) : ctor_(ctor) {
}

std::string Module::ToString() const {
  return "Module";
}

Handler* Module::GetHandler() const {
  ASSERT_LOG(handler_ != nullptr, "Can't get handler when it's not started");
  return handler_;
}

DumpsysDataFinisher EmptyDumpsysDataFinisher = [](DumpsysDataBuilder* dumpsys_data_builder) {};
DumpsysDataFinisher Module::GetDumpsysData(flatbuffers::FlatBufferBuilder* builder) const {
  return EmptyDumpsysDataFinisher;
}

const ModuleRegistry* Module::GetModuleRegistry() const {
  return registry_;
}

Module* Module::GetDependency(const ModuleFactory* module) const {
  for (auto& dependency : dependencies_.list_) {
    if (dependency == module) {
      return registry_->Get(module);
    }
  }

  ASSERT_LOG(false, "Module was not listed as a dependency in ListDependencies");
}

Module* ModuleRegistry::Get(const ModuleFactory* module) const {
  auto instance = started_modules_.find(module);
  ASSERT(instance != started_modules_.end());
  return instance->second;
}

bool ModuleRegistry::IsStarted(const ModuleFactory* module) const {
  return started_modules_.find(module) != started_modules_.end();
}

void ModuleRegistry::Start(ModuleList* modules, Thread* thread) {
  for (auto it = modules->list_.begin(); it != modules->list_.end(); it++) {
    Start(*it, thread);
  }
}

void ModuleRegistry::set_registry_and_handler(Module* instance, Thread* thread) const {
  instance->registry_ = this;
  instance->handler_ = new Handler(thread);
}

Module* ModuleRegistry::Start(const ModuleFactory* module, Thread* thread) {
  auto started_instance = started_modules_.find(module);
  if (started_instance != started_modules_.end()) {
    return started_instance->second;
  }

  Module* instance = module->ctor_();
  last_instance_ = "starting " + instance->ToString();
  set_registry_and_handler(instance, thread);

  instance->ListDependencies(&instance->dependencies_);
  Start(&instance->dependencies_, thread);

  instance->Start();
  start_order_.push_back(module);
  started_modules_[module] = instance;
  return instance;
}

void ModuleRegistry::StopAll() {
  // Since modules were brought up in dependency order, it is safe to tear down by going in reverse order.
  for (auto it = start_order_.rbegin(); it != start_order_.rend(); it++) {
    auto instance = started_modules_.find(*it);
    ASSERT(instance != started_modules_.end());
    last_instance_ = "stopping " + instance->second->ToString();

    // Clear the handler before stopping the module to allow it to shut down gracefully.
    LOG_INFO("Stopping Handler of Module %s", instance->second->ToString().c_str());
    instance->second->handler_->Clear();
    instance->second->handler_->WaitUntilStopped(kModuleStopTimeout);
    LOG_INFO("Stopping Module %s", instance->second->ToString().c_str());
    instance->second->Stop();
  }
  for (auto it = start_order_.rbegin(); it != start_order_.rend(); it++) {
    auto instance = started_modules_.find(*it);
    ASSERT(instance != started_modules_.end());
    delete instance->second->handler_;
    delete instance->second;
    started_modules_.erase(instance);
  }

  ASSERT(started_modules_.empty());
  start_order_.clear();
}

os::Handler* ModuleRegistry::GetModuleHandler(const ModuleFactory* module) const {
  auto started_instance = started_modules_.find(module);
  if (started_instance != started_modules_.end()) {
    return started_instance->second->GetHandler();
  }
  return nullptr;
}

void ModuleDumper::DumpState(std::string* output) const {
  ASSERT(output != nullptr);

  flatbuffers::FlatBufferBuilder builder(1024);
  auto title = builder.CreateString(title_);

  auto init_flags_offset = dumpsys::InitFlags::Dump(&builder);

  std::queue<DumpsysDataFinisher> queue;
  for (auto it = module_registry_.start_order_.rbegin(); it != module_registry_.start_order_.rend(); it++) {
    auto instance = module_registry_.started_modules_.find(*it);
    ASSERT(instance != module_registry_.started_modules_.end());
    queue.push(instance->second->GetDumpsysData(&builder));
  }

  DumpsysDataBuilder data_builder(builder);
  data_builder.add_title(title);
  data_builder.add_init_flags(init_flags_offset);

  while (!queue.empty()) {
    queue.front()(&data_builder);
    queue.pop();
  }

  builder.Finish(data_builder.Finish());
  *output = std::string(builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize());
}

}  // namespace bluetooth
