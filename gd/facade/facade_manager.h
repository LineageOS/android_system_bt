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
#include <list>

#include <grpc++/grpc++.h>

#include "hal/hci_hal.h"

namespace bluetooth {
namespace facade {

class FacadeConfig {
 public:
  static FacadeConfig* Get() {
    static FacadeConfig instance;
    return &instance;
  }

  void SetGrpcPort(int port) {
    grpc_port_ = port;
  }

  int GetGrpcPort() {
    return grpc_port_;
  }

 private:
  FacadeConfig() = default;
  int grpc_port_ = 8899;
};

class FacadeManager {
 public:
  enum class Module {
    HciHal,
  };

  static FacadeManager* Get() {
    static FacadeManager instance;
    return &instance;
  }

  void EnableModule(Module module);

  void StartUp();

  void ShutDown();

  // Blocks for incoming gRPC requests
  void GrpcMainLoop();

 private:
  std::unique_ptr<::grpc::Server> server_ = nullptr;
  std::unique_ptr<::grpc::ServerCompletionQueue> grpc_completion_queue_ = nullptr;
  std::list<Module> enabled_modules_;
  void start_server(const std::string& address, int port);
  void stop_server();
  ::grpc::ServerCompletionQueue* get_grpc_completion_queue();
};

// Cert facade for each layer
class CertFacade {
 public:
  virtual ~CertFacade() = default;

  // Initialize gRPC service, asynchronous request handlers, and other resources here.
  // This should be invoked after CompletionQueue is started.
  virtual void StartUp(::grpc::ServerCompletionQueue* cq) {}

  // Do the clean up here
  // This should be invoked before CompletionQueue is shutdown.
  virtual void ShutDown() {}

  // Each facade has a gRPC service that implements stubs from its api proto. The service instance should exist all
  // the time, so static storage is recommended.
  virtual ::grpc::Service* GetModuleGrpcService() const = 0;
};

}  // namespace facade
}  // namespace bluetooth
