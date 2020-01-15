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

namespace bluetooth {
namespace test {
namespace headless {

template <typename T>
using ExecutionUnit = std::function<T()>;

class Headless {
 public:
  Headless() = default;
  virtual ~Headless() = default;

 protected:
  virtual void SetUp();
  virtual void TearDown();
};

class Test : public Headless {
 public:
  template <typename T>
  T Run(ExecutionUnit<T> func) {
    SetUp();
    T rc = func();
    TearDown();
    return rc;
  }
};

}  // namespace headless
}  // namespace test
}  // namespace bluetooth
