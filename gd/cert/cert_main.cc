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

#include "stack_manager.h"

#include <csignal>

#include "grpc/grpc_module.h"
#include "hal/cert/cert.h"
#include "hal/hci_hal.h"
#include "hal/hci_hal_host_rootcanal.h"
#include "hal/snoop_logger.h"
#include "module.h"
#include "os/thread.h"

using ::bluetooth::Module;
using ::bluetooth::ModuleList;
using ::bluetooth::StackManager;
using ::bluetooth::grpc::GrpcModule;
using ::bluetooth::os::Thread;

namespace {
StackManager* stack;

void interrupt_handler(int) {
  stack->GetInstance<GrpcModule>()->StopServer();
}
}  // namespace

int main(int argc, const char** argv) {
  int port = 8898;

  const std::string arg_grpc_port = "--port=";
  const std::string arg_rootcanal_port = "--rootcanal-port=";
  const std::string arg_btsnoop_path = "--btsnoop=";
  std::string btsnoop_path;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg.find(arg_grpc_port) == 0) {
      auto port_number = arg.substr(arg_grpc_port.size());
      port = std::stoi(port_number);
    }
    if (arg.find(arg_rootcanal_port) == 0) {
      auto port_number = arg.substr(arg_rootcanal_port.size());
      ::bluetooth::hal::HciHalHostRootcanalConfig::Get()->SetPort(std::stoi(port_number));
    }
    if (arg.find(arg_btsnoop_path) == 0) {
      btsnoop_path = arg.substr(arg_btsnoop_path.size());
      ::bluetooth::hal::SnoopLogger::SetFilePath(btsnoop_path);
    }
  }

  ModuleList modules;
  modules.add<::bluetooth::hal::HciHal>();
  modules.add<GrpcModule>();
  modules.add<::bluetooth::hal::cert::HalCertModule>();

  Thread* stack_thread = new Thread("cert_stack_thread", Thread::Priority::NORMAL);

  stack = new StackManager();
  stack->StartUp(&modules, stack_thread);

  GrpcModule* grpc_module = stack->GetInstance<GrpcModule>();
  grpc_module->StartServer("0.0.0.0", port);

  signal(SIGINT, interrupt_handler);
  auto wait_thread = std::thread([grpc_module] { grpc_module->RunGrpcLoop(); });
  wait_thread.join();

  stack->ShutDown();
  delete stack;
  delete stack_thread;

  return 0;
}
