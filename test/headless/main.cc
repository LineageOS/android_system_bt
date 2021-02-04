/*
 * Copyright 2020 The Android Open Source Project
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

#define LOG_TAG "bt_headless"

#include <iostream>
#include <unordered_map>

#include <sys/wait.h>
#include <unistd.h>

#include "base/logging.h"     // LOG() stdout and android log
#include "osi/include/log.h"  // android log only
#include "test/headless/connect/connect.h"
#include "test/headless/dumpsys/dumpsys.h"
#include "test/headless/get_options.h"
#include "test/headless/headless.h"
#include "test/headless/nop/nop.h"
#include "test/headless/pairing/pairing.h"
#include "test/headless/read/read.h"
#include "test/headless/sdp/sdp.h"

using namespace bluetooth::test::headless;

namespace {

void clear_logcat() {
  int pid;
  if ((pid = fork())) {
    // parent process
    int status;
    waitpid(pid, &status, 0);  // wait for the child to exit
    ASSERT_LOG(WIFEXITED(status), "Unable to clear logcat");
  } else {
    // child process
    const char exec[] = "/system/bin/logcat";
    const char arg0[] = "-c";

    execl(exec, exec, arg0, NULL);

    ASSERT_LOG(false, "Should not return from exec process");
  }
}

class Main : public HeadlessTest<int> {
 public:
  Main(const bluetooth::test::headless::GetOpt& options)
      : HeadlessTest<int>(options) {
    test_nodes_.emplace(
        "dumpsys",
        std::make_unique<bluetooth::test::headless::Dumpsys>(options));
    test_nodes_.emplace(
        "connect",
        std::make_unique<bluetooth::test::headless::Connect>(options));
    test_nodes_.emplace(
        "nop", std::make_unique<bluetooth::test::headless::Nop>(options));
    test_nodes_.emplace(
        "pairing",
        std::make_unique<bluetooth::test::headless::Pairing>(options));
    test_nodes_.emplace(
        "read", std::make_unique<bluetooth::test::headless::Read>(options));
    test_nodes_.emplace(
        "sdp", std::make_unique<bluetooth::test::headless::Sdp>(options));
  }

  int Run() override {
    if (options_.close_stderr_) {
      fclose(stderr);
    }

    if (options_.clear_logcat_) {
      clear_logcat();
    }

    return HeadlessTest<int>::Run();
  }
};

}  // namespace

int main(int argc, char** argv) {
  fflush(nullptr);
  setvbuf(stdout, nullptr, _IOLBF, 0);

  bluetooth::test::headless::GetOpt options(argc, argv);
  if (!options.IsValid()) {
    return -1;
  }

  Main main(options);
  return main.Run();
}
