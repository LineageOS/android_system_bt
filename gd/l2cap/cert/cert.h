#pragma once

#include <grpc++/grpc++.h>

#include "grpc/grpc_module.h"
#include "l2cap/l2cap_layer.h"

namespace bluetooth {
namespace l2cap {
namespace cert {

class L2capModuleCertService;

class L2capModuleCertModule : public ::bluetooth::grpc::GrpcFacadeModule {
 public:
  static const ModuleFactory Factory;

  void ListDependencies(ModuleList* list) override;
  void Start() override;
  void Stop() override;

  ::grpc::Service* GetService() const override;

 private:
  L2capModuleCertService* service_;
};

}  // namespace cert
}  // namespace l2cap
}  // namespace bluetooth