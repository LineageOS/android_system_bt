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

#include "common/bind.h"
#include "common/callback.h"

namespace bluetooth {
namespace common {

class IPostableContext {
 public:
  virtual ~IPostableContext(){};
  virtual void Post(OnceClosure closure) = 0;
};

template <typename R, typename... Args>
class ContextualOnceCallback;

template <typename R, typename... Args>
class ContextualOnceCallback<R(Args...)> {
 public:
  ContextualOnceCallback(common::OnceCallback<R(Args...)>&& callback, IPostableContext* context)
      : callback_(std::move(callback)), context_(context) {}

  constexpr ContextualOnceCallback() = default;

  DISALLOW_COPY_AND_ASSIGN(ContextualOnceCallback);

  ContextualOnceCallback(ContextualOnceCallback&&) noexcept = default;
  ContextualOnceCallback& operator=(ContextualOnceCallback&&) noexcept = default;

  void Invoke(Args... args) {
    context_->Post(common::BindOnce(std::move(callback_), std::forward<Args>(args)...));
  }

 private:
  common::OnceCallback<R(Args...)> callback_;
  IPostableContext* context_;
};

}  // namespace common
}  // namespace bluetooth
