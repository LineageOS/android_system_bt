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

#include <functional>
#include <vector>
#include <map>

#include "os/log.h"
#include "os/handler.h"
#include "os/thread.h"

namespace bluetooth {

class Module;
class ModuleRegistry;

class ModuleFactory {
 friend ModuleRegistry;
 public:
  ModuleFactory(std::function<Module*()> ctor);

 private:
  std::function<Module*()> ctor_;
};

class ModuleList {
 friend ModuleRegistry;
 friend Module;
 public:
  template <class T>
  void add() {
    list_.push_back(&T::Factory);
  }

 private:
  std::vector<const ModuleFactory*> list_;
};

// Each leaf node module must have a factory like so:
//
// static const ModuleFactory Factory;
//
// which will provide a constructor for the module registry to call.
// The module registry will also use the factory as the identifier
// for that module.
class Module {
 friend ModuleRegistry;
 public:
  virtual ~Module() = default;
 protected:
  // Populate the provided list with modules that must start before yours
  virtual void ListDependencies(ModuleList* list) = 0;

  // You can grab your started dependencies during or after this call
  // using GetDependency(), or access the module registry via GetModuleRegistry()
  virtual void Start() = 0;

  // Release all resources, you're about to be deleted
  virtual void Stop() = 0;

  ::bluetooth::os::Handler* GetHandler();

  ModuleRegistry* GetModuleRegistry();

  template <class T>
  T* GetDependency() const {
    return static_cast<T*>(GetDependency(&T::Factory));
  }

 private:
  Module* GetDependency(const ModuleFactory* module) const;

  ::bluetooth::os::Handler* handler_;
  ModuleList dependencies_;
  ModuleRegistry* registry_;
};

class ModuleRegistry {
 friend Module;
 friend class StackManager;
 public:
  template <class T>
  bool IsStarted() const {
    return IsStarted(&T::Factory);
  }

  bool IsStarted(const ModuleFactory* factory) const;

  // Start all the modules on this list and their dependencies
  // in dependency order
  void Start(ModuleList* modules, ::bluetooth::os::Thread* thread);

  template <class T>
  T* Start(::bluetooth::os::Thread* thread) {
    return static_cast<T*>(Start(&T::Factory, thread));
  }

  Module* Start(const ModuleFactory* id, ::bluetooth::os::Thread* thread);

  // Stop all running modules in reverse order of start
  void StopAll();

  // Helper for dependency injection in test code. DO NOT USE in prod code!
  // Ownership of |instance| is transferred to the registry.
  void inject_test_module(const ModuleFactory* module, Module* instance, os::Thread* thread);

  // Helper for dependency injection in test code. DO NOT USE in prod code!
  template <class T>
  T* get_module_under_test() const {
    return static_cast<T*>(Get(&T::Factory));
  }

 private:
  Module* Get(const ModuleFactory* module) const;
  std::map<const ModuleFactory*, Module*> started_modules_;
  std::vector<const ModuleFactory*> start_order_;
};

}  // namespace bluetooth
