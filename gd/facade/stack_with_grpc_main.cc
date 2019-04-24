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
#include "hal/hci_hal_host_rootcanal.h"

#include <csignal>
#include <string>
#include <thread>

using ::bluetooth::facade::FacadeConfig;
using ::bluetooth::facade::FacadeManager;
using ::bluetooth::hal::HciHalHostRootcanalConfig;

namespace {
void interrupt_handler(int) {
  FacadeManager::Get()->ShutDown();
}
}  // namespace

// The entry point for the binary with libbluetooth + facades
int main(int argc, const char** argv) {
  signal(SIGINT, interrupt_handler);

  const std::string arg_grpc_port = "--port=";
  const std::string arg_rootcanal_port = "--rootcanal-port=";
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg.find(arg_grpc_port) == 0) {
      auto port_number = arg.substr(arg_grpc_port.size());
      FacadeConfig::Get()->SetGrpcPort(std::stoi(port_number));
    }
    if (arg.find(arg_rootcanal_port) == 0) {
      auto port_number = arg.substr(arg_rootcanal_port.size());
      HciHalHostRootcanalConfig::Get()->SetPort(std::stoi(port_number));
    }
  }

  // TODO: This should be run-time configurable
  FacadeManager::Get()->EnableModule(FacadeManager::Module::HciHal);

  FacadeManager::Get()->StartUp();
  auto wait_thread = std::thread([] { FacadeManager::Get()->GrpcMainLoop(); });
  wait_thread.join();
  FacadeManager::Get()->ShutDown();

  return 0;
}
