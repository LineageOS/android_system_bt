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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <csignal>
#include <cstring>
#include <string>
#include <thread>

#include "cert/grpc_root_server.h"
#include "grpc/grpc_module.h"
#include "hal/cert/cert.h"
#include "hal/hci_hal.h"
#include "hal/hci_hal_host_rootcanal.h"
#include "hal/snoop_logger.h"

using ::bluetooth::Module;
using ::bluetooth::ModuleList;
using ::bluetooth::StackManager;
using ::bluetooth::grpc::GrpcModule;
using ::bluetooth::os::Thread;

namespace {
::bluetooth::cert::GrpcRootServer grpc_root_server;

void interrupt_handler(int) {
  grpc_root_server.StopServer();
}
}  // namespace

int main(int argc, const char** argv) {
  int root_server_port = 8897;
  int grpc_port = 8899;

  const std::string arg_grpc_root_server_port = "--root-server-port=";
  const std::string arg_grpc_server_port = "--grpc-port=";
  const std::string arg_rootcanal_port = "--rootcanal-port=";
  const std::string arg_btsnoop_path = "--btsnoop=";
  std::string btsnoop_path;
  const std::string arg_tester_signal_socket = "--tester-signal-socket=";
  std::string tester_signal_path;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg.find(arg_grpc_root_server_port) == 0) {
      auto port_number = arg.substr(arg_grpc_root_server_port.size());
      root_server_port = std::stoi(port_number);
    }
    if (arg.find(arg_grpc_server_port) == 0) {
      auto port_number = arg.substr(arg_grpc_server_port.size());
      grpc_port = std::stoi(port_number);
    }
    if (arg.find(arg_rootcanal_port) == 0) {
      auto port_number = arg.substr(arg_rootcanal_port.size());
      ::bluetooth::hal::HciHalHostRootcanalConfig::Get()->SetPort(std::stoi(port_number));
    }
    if (arg.find(arg_btsnoop_path) == 0) {
      btsnoop_path = arg.substr(arg_btsnoop_path.size());
      ::bluetooth::hal::SnoopLogger::SetFilePath(btsnoop_path);
    }
    if (arg.find(arg_tester_signal_socket) == 0) {
      tester_signal_path = arg.substr(arg_tester_signal_socket.size());
    }
  }

  signal(SIGINT, interrupt_handler);
  grpc_root_server.StartServer("0.0.0.0", root_server_port, grpc_port);
  int tester_signal_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, tester_signal_path.c_str(), tester_signal_path.size() + 1);
  connect(tester_signal_socket, (sockaddr*)&addr, sizeof(addr));
  close(tester_signal_socket);
  auto wait_thread = std::thread([] { grpc_root_server.RunGrpcLoop(); });
  wait_thread.join();

  return 0;
}
