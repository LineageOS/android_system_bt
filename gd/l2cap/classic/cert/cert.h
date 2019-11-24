#pragma once

#include <grpc++/grpc++.h>

#include "grpc/grpc_module.h"

namespace bluetooth {
namespace l2cap {
namespace classic {
namespace cert {

class L2capClassicModuleCertService;

class L2capClassicModuleCertModule : public ::bluetooth::grpc::GrpcFacadeModule {
 public:
  static const ModuleFactory Factory;

  void ListDependencies(ModuleList* list) override;
  void Start() override;
  void Stop() override;

  ::grpc::Service* GetService() const override;

 private:
  L2capClassicModuleCertService* service_;
};

}  // namespace cert
}  // namespace classic
}  // namespace l2cap
}  // namespace bluetooth