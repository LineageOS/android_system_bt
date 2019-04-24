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

#include <list>
#include <mutex>

#include <grpc++/grpc++.h>

#include "facade/facade_manager.h"

namespace bluetooth {
namespace hal {
namespace facade {
// Get cert facade. This instance has static storage.
::bluetooth::facade::CertFacade* GetFacadeModule();

class HalFacadeModule : public ::bluetooth::facade::CertFacade {
 public:
  void StartUp(::grpc::ServerCompletionQueue* cq) override;

  void ShutDown() override;

  ::grpc::Service* GetModuleGrpcService() const override;

  struct HciEvtListener {
    virtual ~HciEvtListener() = default;
    virtual void operator()(const hal::HciPacket&) {}
  };

  void RegisterHciEvtListener(HciEvtListener* listener);
  void UnregisterHciEvtListener(HciEvtListener* listener);

  struct HciAclListener {
    virtual ~HciAclListener() = default;
    virtual void operator()(const hal::HciPacket&) {}
  };

  void RegisterHciAclListener(HciAclListener* listener);
  void UnregisterHciAclListener(HciAclListener* listener);

  struct HciScoListener {
    virtual ~HciScoListener() = default;
    virtual void operator()(const hal::HciPacket&) {}
  };

  void RegisterHciScoListener(HciScoListener* listener);
  void UnregisterHciScoListener(HciScoListener* listener);

 private:
  std::mutex mutex_;
  friend class IncomingPacketCallback;
  std::list<HciEvtListener*> registered_evt_listener_;
  std::list<HciAclListener*> registered_acl_listener_;
  std::list<HciScoListener*> registered_sco_listener_;
};

}  // namespace facade
}  // namespace hal
}  // namespace bluetooth
