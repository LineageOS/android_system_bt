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

#include "shim/dumpsys.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "module.h"
#include "os/thread.h"
#include "test_gen/dumpsys_test_data_bin.h"

namespace testing {

using bluetooth::TestModuleRegistry;
using namespace bluetooth;

namespace {

bool SimpleJsonValidator(int fd) {
  char buf{0};
  bool within_double_quotes{false};
  int left_bracket{0}, right_bracket{0};
  while (read(fd, &buf, 1) != -1) {
    switch (buf) {
      case '"':
        within_double_quotes = !within_double_quotes;
        break;
      case '{':
        if (!within_double_quotes) {
          left_bracket++;
        }
        break;
      case '}':
        if (!within_double_quotes) {
          right_bracket++;
        }
        break;
      default:
        break;
    }
  }
  return left_bracket == right_bracket;
}

}  // namespace

// To create dumpsys_test_header_bin.h:
// make bluetooth_flatbuffer_bundler
// ${ANDROID_BUILD_TOP}/out/host/linux-x86/bin/bluetooth_flatbuffer_bundler -w -m bluetooth.DumpsysData -f
// test_gen/dumpsys_test_data_bin -n bluetooth::test test_gen/*

class DumpsysTest : public Test {
 protected:
  void SetUp() override {
    dumpsys_module_ = new bluetooth::shim::Dumpsys(bluetooth::test::GetBundledSchemaData());
    fake_registry_.InjectTestModule(&shim::Dumpsys::Factory, dumpsys_module_);
  }

  void TearDown() override {
    fake_registry_.StopAll();
  }

  TestModuleRegistry fake_registry_;
  os::Thread& thread_ = fake_registry_.GetTestThread();
  bluetooth::shim::Dumpsys* dumpsys_module_ = nullptr;
  os::Handler* client_handler_ = nullptr;
};

TEST_F(DumpsysTest, dump) {
  int sv[2];
  int rc = socketpair(AF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
  ASSERT(rc == 0);
  dumpsys_module_->Dump(sv[0], nullptr);
  ASSERT(SimpleJsonValidator(sv[1]));
}

}  // namespace testing
