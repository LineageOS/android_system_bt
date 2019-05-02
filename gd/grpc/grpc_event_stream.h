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

#include <grpc++/grpc++.h>

#include <chrono>

#include "common/blocking_queue.h"
#include "facade/common.pb.h"
#include "os/log.h"

namespace bluetooth {
namespace grpc {

template <typename RES, typename EVENT>
class GrpcEventStreamCallback {
 public:
  virtual ~GrpcEventStreamCallback() = default;
  virtual void OnSubscribe() {}
  virtual void OnUnsubscribe() {}
  virtual void OnWriteResponse(RES* response, const EVENT& event) = 0;
};

template <typename RES, typename EVENT>
class GrpcEventStream {
 public:
  explicit GrpcEventStream(GrpcEventStreamCallback<RES, EVENT>* callback) : callback_(callback) {}

  void OnIncomingEvent(const EVENT& event) {
    if (subscribed_) {
      event_queue_.push(event);
    }
  }

  ::grpc::Status HandleRequest(::grpc::ServerContext* context, const ::bluetooth::facade::EventStreamRequest* request,
                               ::grpc::ServerWriter<RES>* writer) {
    ::bluetooth::facade::EventSubscriptionMode subscription_mode = request->subscription_mode();
    ::bluetooth::facade::EventFetchMode fetch_mode = request->fetch_mode();
    uint32_t timeout_ms = request->timeout_ms();
    if (timeout_ms == 0) {
      timeout_ms = 3000;
    }

    if (subscription_mode == ::bluetooth::facade::SUBSCRIBE) {
      event_queue_.clear();
      callback_->OnSubscribe();
      subscribed_ = true;
    }

    if (fetch_mode == ::bluetooth::facade::AT_LEAST_ONE) {
      RES response;
      EVENT event;
      if (!event_queue_.take_for(std::chrono::milliseconds(timeout_ms), event)) {
        return ::grpc::Status(::grpc::StatusCode::DEADLINE_EXCEEDED, "timeout exceeded");
      }
      callback_->OnWriteResponse(&response, event);
      writer->Write(response);
    }

    // fetch all current remaining items and append to AT_LEAST_ONE query if present
    if (fetch_mode == ::bluetooth::facade::ALL_CURRENT || fetch_mode == ::bluetooth::facade::AT_LEAST_ONE) {
      while (!event_queue_.empty()) {
        RES response;
        EVENT event = event_queue_.take();
        callback_->OnWriteResponse(&response, event);
        writer->Write(response);
      }
    }

    if (subscription_mode == ::bluetooth::facade::UNSUBSCRIBE) {
      subscribed_ = false;
      event_queue_.clear();
      callback_->OnUnsubscribe();
    }

    return ::grpc::Status::OK;
  }

 private:
  common::BlockingQueue<EVENT> event_queue_;
  GrpcEventStreamCallback<RES, EVENT>* callback_;
  bool subscribed_ = false;
};

}  // namespace grpc
}  // namespace bluetooth
