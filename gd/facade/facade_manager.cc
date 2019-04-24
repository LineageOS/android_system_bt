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

#include "facade/facade_manager.h"

#include "grpc/async_grpc.h"
#include "hal/facade/facade.h"
#include "os/log.h"
#include "stack_manager.h"

using ::bluetooth::hal::HciPacket;

using ::grpc::Server;
using ::grpc::ServerBuilder;

namespace {

::bluetooth::facade::CertFacade* module_enum_to_module(const ::bluetooth::facade::FacadeManager::Module& module) {
  switch (module) {
    case ::bluetooth::facade::FacadeManager::Module::HciHal:
      return ::bluetooth::hal::facade::GetFacadeModule();
  }
  return nullptr;
}
}  // namespace

namespace bluetooth {
namespace facade {

void FacadeManager::EnableModule(Module module) {
  enabled_modules_.push_back(module);
}

void FacadeManager::StartUp() {
  StackManager::Get()->StartUp();
  LOG_INFO("%d", FacadeConfig::Get()->GetGrpcPort());
  start_server("0.0.0.0", FacadeConfig::Get()->GetGrpcPort());

  for (const auto& enabled_module : enabled_modules_) {
    auto* module = module_enum_to_module(enabled_module);
    module->StartUp(get_grpc_completion_queue());
  }
}

void FacadeManager::start_server(const std::string& address, int port) {
  std::string listening_port = address + ":" + std::to_string(port);
  ServerBuilder builder;
  builder.AddListeningPort(listening_port, ::grpc::InsecureServerCredentials());

  grpc_completion_queue_ = builder.AddCompletionQueue();
  for (const auto& enabled_module : enabled_modules_) {
    auto* module = module_enum_to_module(enabled_module);
    builder.RegisterService(module->GetModuleGrpcService());
  }

  server_ = builder.BuildAndStart();
}

void FacadeManager::ShutDown() {
  stop_server();

  for (const auto& enabled_module : enabled_modules_) {
    auto* module = module_enum_to_module(enabled_module);
    module->ShutDown();
  }

  StackManager::Get()->ShutDown();
}

void FacadeManager::stop_server() {
  server_->Shutdown();
  grpc_completion_queue_->Shutdown();
}

::grpc::ServerCompletionQueue* FacadeManager::get_grpc_completion_queue() {
  auto* queue = grpc_completion_queue_.get();
  ASSERT(queue != nullptr);
  return queue;
}

void FacadeManager::GrpcMainLoop() {
  void* tag;
  bool ok;
  while (true) {
    if (!grpc_completion_queue_->Next(&tag, &ok)) {
      LOG_INFO("gRPC is shutdown");
      break;
    }
    auto* data = static_cast<grpc::GrpcAsyncEventCallback*>(tag);
    (*data)(ok);
  }
}

}  // namespace facade
}  // namespace bluetooth
