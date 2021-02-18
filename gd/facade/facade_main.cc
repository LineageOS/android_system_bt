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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <csignal>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include "stack_manager.h"

// clang-format off
#include <client/linux/handler/exception_handler.h>
#include <backtrace/Backtrace.h>
#include <backtrace/backtrace_constants.h>
// clang-format on

#include "common/init_flags.h"
#include "facade/grpc_root_server.h"
#include "hal/hci_hal_host_rootcanal.h"
#include "hal/snoop_logger.h"
#include "os/log.h"
#include "os/parameter_provider.h"
#include "os/system_properties.h"

using ::bluetooth::ModuleList;
using ::bluetooth::StackManager;
using ::bluetooth::hal::HciHalHostRootcanalConfig;
using ::bluetooth::os::Thread;

extern "C" const char* __asan_default_options() {
  return "detect_container_overflow=0";
}

namespace {
::bluetooth::facade::GrpcRootServer grpc_root_server;

struct sigaction old_act = {};
void interrupt_handler(int signal_number) {
  LOG_INFO("Stopping gRPC root server due to signal: %s[%d]", strsignal(signal_number), signal_number);
  grpc_root_server.StopServer();
  if (old_act.sa_handler != nullptr) {
    LOG_INFO("Calling saved signal handler");
    old_act.sa_handler(signal_number);
  }
}
struct sigaction new_act = {.sa_handler = interrupt_handler};

bool crash_callback(const void* crash_context, size_t crash_context_size, void* context) {
  pid_t tid = BACKTRACE_CURRENT_THREAD;
  if (crash_context_size >= sizeof(google_breakpad::ExceptionHandler::CrashContext)) {
    auto* ctx = static_cast<const google_breakpad::ExceptionHandler::CrashContext*>(crash_context);
    tid = ctx->tid;
    int signal_number = ctx->siginfo.si_signo;
    LOG_ERROR("Process crashed, signal: %s[%d], tid: %d", strsignal(signal_number), signal_number, ctx->tid);
  } else {
    LOG_ERROR("Process crashed, signal: unknown, tid: unknown");
  }
  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(BACKTRACE_CURRENT_PROCESS, tid));
  if (backtrace == nullptr) {
    LOG_ERROR("Failed to create backtrace object");
    return false;
  }
  if (!backtrace->Unwind(0)) {
    LOG_ERROR("backtrace->Unwind failed");
    return false;
  }
  LOG_ERROR("Backtrace:");
  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    LOG_ERROR("%s", backtrace->FormatFrameData(i).c_str());
  }
  return true;
}

}  // namespace

// The entry point for the binary with libbluetooth + facades
int main(int argc, const char** argv) {
  google_breakpad::MinidumpDescriptor descriptor(google_breakpad::MinidumpDescriptor::kMicrodumpOnConsole);
  google_breakpad::ExceptionHandler eh(descriptor, nullptr, nullptr, nullptr, true, -1);
  eh.set_crash_handler(crash_callback);

  int root_server_port = 8897;
  int grpc_port = 8899;
  int signal_port = 8895;

  bluetooth::common::InitFlags::SetAllForTesting();

  const std::string arg_grpc_root_server_port = "--root-server-port=";
  const std::string arg_grpc_server_port = "--grpc-port=";
  const std::string arg_rootcanal_port = "--rootcanal-port=";
  const std::string arg_signal_port = "--signal-port=";
  const std::string arg_btsnoop_path = "--btsnoop=";
  const std::string arg_btsnooz_path = "--btsnooz=";
  const std::string arg_btconfig_path = "--btconfig=";
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
      HciHalHostRootcanalConfig::Get()->SetPort(std::stoi(port_number));
    }
    if (arg.find(arg_btsnoop_path) == 0) {
      auto btsnoop_path = arg.substr(arg_btsnoop_path.size());
      ::bluetooth::os::ParameterProvider::OverrideSnoopLogFilePath(btsnoop_path);
      CHECK(::bluetooth::os::SetSystemProperty(
          ::bluetooth::hal::SnoopLogger::kBtSnoopLogModeProperty, ::bluetooth::hal::SnoopLogger::kBtSnoopLogModeFull));
    }
    if (arg.find(arg_btsnooz_path) == 0) {
      auto btsnooz_path = arg.substr(arg_btsnooz_path.size());
      ::bluetooth::os::ParameterProvider::OverrideSnoozLogFilePath(btsnooz_path);
    }
    if (arg.find(arg_btconfig_path) == 0) {
      auto btconfig_path = arg.substr(arg_btconfig_path.size());
      ::bluetooth::os::ParameterProvider::OverrideConfigFilePath(btconfig_path);
    }
    if (arg.find(arg_signal_port) == 0) {
      auto port_number = arg.substr(arg_signal_port.size());
      signal_port = std::stoi(port_number);
    }
  }

  sigaction(SIGINT, &new_act, &old_act);
  grpc_root_server.StartServer("0.0.0.0", root_server_port, grpc_port);
  int tester_signal_socket = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(signal_port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  connect(tester_signal_socket, (sockaddr*)&addr, sizeof(addr));
  close(tester_signal_socket);
  auto wait_thread = std::thread([] { grpc_root_server.RunGrpcLoop(); });
  wait_thread.join();

  return 0;
}
