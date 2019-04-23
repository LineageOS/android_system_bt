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

#include <functional>
#include <future>
#include <memory>
#include <mutex>

#include <grpc++/grpc++.h>

#include "os/log.h"

namespace bluetooth {
namespace grpc {

// To be passed to gRPC async invocations as tag.
// Function is called when the CompletionQueue.Next() returns this tag.
// Then, user needs to delete this object.
using GrpcAsyncEventCallback = std::function<void(bool)>;

template <typename REQ, typename RES>
class GrpcAsyncServerStreamingHandler {
 public:
  virtual ~GrpcAsyncServerStreamingHandler() = default;

  // Implementation for requesting the next specific type RPC, using provided parameters.
  virtual void OnReadyForNextRequest(::grpc::ServerContext*, REQ* req, ::grpc::ServerAsyncWriter<RES>* res,
                                     ::grpc::CompletionQueue* new_call_cq,
                                     ::grpc::ServerCompletionQueue* notification_cq, void* tag) = 0;

  virtual void OnRpcRequestReceived(REQ req) = 0;

  virtual void OnRpcRequestFailed() {}

  virtual void OnRpcFinished() {}

  virtual void OnWriteSuccess() {}
};

// Provides API to upper layer users to control (request, write, finish) a server-streaming asynchronous RPC.
// When each API is done, callback will be sent to the given GrpcAsyncServerStreamingHandler.
// Each control box can take one active RPC at one time.

// TODO: problems with this control box:
//  1. RequestNewRpc is async, but Write and Stop is blocking users. Do we want to do this?
//  2. Callback to user is done in the gRPC thread. Let's create a pool thread to give it to user?
//  3. Currently it uses promise to synchronize between events. If we use os/handler it should be easier.
template <typename REQ, typename RES>
class GrpcAsyncServerStreamingControlBox {
 public:
  GrpcAsyncServerStreamingControlBox(GrpcAsyncServerStreamingHandler<REQ, RES>* async_handler,
                                     ::grpc::ServerCompletionQueue* cq)
      : async_handler_(async_handler), cq_(cq) {}

  void RequestNewRpc() {
    ASSERT(my_state_ == MyState::IDLE);
    context_ = std::make_unique<::grpc::ServerContext>();
    req_ = std::make_unique<REQ>();
    res_ = std::make_unique<::grpc::ServerAsyncWriter<RES>>(context_.get());
    request_done_ = std::make_unique<GrpcAsyncEventCallback>([this](bool ok) { this->RequestDone(ok); });
    async_handler_->OnReadyForNextRequest(context_.get(), req_.get(), res_.get(), cq_, cq_, request_done_.get());
    my_state_ = MyState::REQUESTING;
  }

  void Write(const RES& res) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (my_state_ == MyState::IDLE || my_state_ == MyState::REQUESTING) {
      LOG_INFO("stream already stopped");
      return;
    }
    ASSERT(my_state_ == MyState::OPEN);
    write_done_ = std::make_unique<GrpcAsyncEventCallback>([this](bool ok) { this->WriteDone(ok); });
    my_state_ = MyState::WRITING;
    res_->Write(res, write_done_.get());
    promise_ = new std::promise<void>();
    auto future = promise_->get_future();
    future.wait();
  }

  void StopStreaming() {
    std::unique_lock<std::mutex> lock(mutex_);
    ASSERT(my_state_ == MyState::OPEN);
    rpc_finish_ = std::make_unique<GrpcAsyncEventCallback>([this](bool ok) { this->RpcFinish(ok); });
    my_state_ = MyState::FINISHING;
    res_->Finish(::grpc::Status::OK, rpc_finish_.get());
    promise_ = new std::promise<void>();
    auto future = promise_->get_future();
    future.wait();
  }

 private:
  void RequestDone(bool ok) {
    ASSERT(my_state_ == MyState::REQUESTING);
    if (ok) {
      async_handler_->OnRpcRequestReceived(*req_);
      my_state_ = MyState::OPEN;
    } else {
      clean_up();
      async_handler_->OnRpcRequestFailed();
      my_state_ = MyState::IDLE;
    }
  }

  void WriteDone(bool ok) {
    ASSERT(my_state_ == MyState::WRITING);
    if (ok) {
      my_state_ = MyState::OPEN;
      async_handler_->OnWriteSuccess();
    } else {
      clean_up();
      my_state_ = MyState::IDLE;
      async_handler_->OnRpcFinished();
    }
    promise_->set_value();
  }

  void RpcFinish(bool ok) {
    ASSERT(ok);
    ASSERT(my_state_ == MyState::FINISHING);
    clean_up();
    my_state_ = MyState::IDLE;
    async_handler_->OnRpcFinished();
    promise_->set_value();
  }

  void clean_up() {
    context_ = nullptr;
    req_ = nullptr;
    res_ = nullptr;
  }

  mutable std::mutex mutex_;
  std::promise<void>* promise_ = nullptr;

  GrpcAsyncServerStreamingHandler<REQ, RES>* async_handler_;
  ::grpc::ServerCompletionQueue* cq_;

  std::unique_ptr<::grpc::ServerContext> context_ = nullptr;
  std::unique_ptr<REQ> req_ = nullptr;
  std::unique_ptr<::grpc::ServerAsyncWriter<RES>> res_ = nullptr;

  std::unique_ptr<GrpcAsyncEventCallback> request_done_ = nullptr;
  std::unique_ptr<GrpcAsyncEventCallback> write_done_ = nullptr;
  std::unique_ptr<GrpcAsyncEventCallback> rpc_finish_ = nullptr;

  enum class MyState { IDLE, REQUESTING, OPEN, WRITING, FINISHING } my_state_ = MyState::IDLE;
};

}  // namespace grpc
}  // namespace bluetooth
