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

#include "grpc/grpc_module.h"
#include "hal/hci_hal_host_rootcanal.h"
#include "hal/facade/facade.h"

#include <csignal>
#include <string>
#include <thread>

#include "stack_manager.h"

using ::bluetooth::hal::HciHalHostRootcanalConfig;
using ::bluetooth::StackManager;
using ::bluetooth::grpc::GrpcModule;
using ::bluetooth::ModuleList;

namespace {
static StackManager* stack;

void interrupt_handler(int) {
  stack->GetInstance<GrpcModule>()->StopServer();
}
}  // namespace

// The entry point for the binary with libbluetooth + facades
int main(int argc, const char** argv) {

  int port = 8899;

  const std::string arg_grpc_port = "--port=";
  const std::string arg_rootcanal_port = "--rootcanal-port=";
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg.find(arg_grpc_port) == 0) {
      auto port_number = arg.substr(arg_grpc_port.size());
      port = std::stoi(port_number);
    }
    if (arg.find(arg_rootcanal_port) == 0) {
      auto port_number = arg.substr(arg_rootcanal_port.size());
      HciHalHostRootcanalConfig::Get()->SetPort(std::stoi(port_number));
    }
  }

  ModuleList modules;
  modules.add<::bluetooth::hal::facade::HalFacadeModule>();

  stack = new StackManager();
  stack->StartUp(&modules);

  GrpcModule* grpc_module = stack->GetInstance<GrpcModule>();
  grpc_module->StartServer("0.0.0.0", port);

  signal(SIGINT, interrupt_handler);
  auto wait_thread = std::thread([grpc_module] { grpc_module->RunGrpcLoop(); });
  wait_thread.join();

  grpc_module->StopServer();
  stack->ShutDown();
  delete stack;

  return 0;
}
