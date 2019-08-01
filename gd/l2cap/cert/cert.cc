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

#include "l2cap/cert/cert.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "common/blocking_queue.h"
#include "grpc/grpc_event_stream.h"
#include "l2cap/cert/api.grpc.pb.h"
#include "l2cap/l2cap_layer.h"
#include "l2cap/l2cap_packets.h"
#include "os/log.h"
#include "packet/raw_builder.h"

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;

using ::bluetooth::facade::EventStreamRequest;
using ::bluetooth::packet::RawBuilder;

namespace bluetooth {
namespace l2cap {
namespace cert {

using namespace facade;

class L2capModuleCertService : public L2capModuleCert::Service {
 public:
  L2capModuleCertService(l2cap::L2capLayer* l2cap_layer, ::bluetooth::os::Handler* facade_handler)
      : l2cap_layer_(l2cap_layer), facade_handler_(facade_handler) {
    ASSERT(l2cap_layer_ != nullptr);
    ASSERT(facade_handler_ != nullptr);
  }

  ::grpc::Status NoOp(::grpc::ServerContext* context, const ::google::protobuf::Empty* request,
                      ::google::protobuf::Empty* response) override {
    return ::grpc::Status::OK;
  }

 private:
  l2cap::L2capLayer* l2cap_layer_;
  ::bluetooth::os::Handler* facade_handler_;
  std::mutex mutex_;
};

void L2capModuleCertModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<l2cap::L2capLayer>();
}

void L2capModuleCertModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new L2capModuleCertService(GetDependency<l2cap::L2capLayer>(), GetHandler());
}

void L2capModuleCertModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* L2capModuleCertModule::GetService() const {
  return service_;
}

const ModuleFactory L2capModuleCertModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new L2capModuleCertModule(); });

}  // namespace cert
}  // namespace l2cap
}  // namespace bluetooth
