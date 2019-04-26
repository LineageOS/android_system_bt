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
// The module registry will also use the Factory as the identifier
// for that module.
class Module {
 friend ModuleRegistry;
 public:
  virtual ~Module() = default;
 protected:
  // Populate the provided list with modules that must start before yours
  virtual void ListDependencies(ModuleList* list) = 0;

  // You can grab your started dependencies from the registry in this call
  virtual void Start(const ModuleRegistry* registry) = 0;

  // Release all resources, you're about to be deleted
  virtual void Stop(const ModuleRegistry* registry) = 0;
};

class ModuleRegistry {
 public:
  template <class T>
  T* GetInstance() const {
    auto instance = started_modules_.find(&T::Factory);
    ASSERT(instance != started_modules_.end());
    return static_cast<T *>(instance->second);
  };

  template <class T>
  bool IsStarted() const {
    return IsStarted(&T::Factory);
  }

  bool IsStarted(const ModuleFactory* factory) const;

  // Start all the modules on this list and their dependencies
  // in dependency order
  void Start(ModuleList* modules);

  template <class T>
  void Start() {
    Start(&T::Factory);
  }

  void Start(const ModuleFactory* id);

  // Stop all running modules in reverse order of start
  void StopAll();

 private:
  std::map<const ModuleFactory*, Module*> started_modules_;
  std::vector<const ModuleFactory*> start_order_;
};

}  // namespace bluetooth
