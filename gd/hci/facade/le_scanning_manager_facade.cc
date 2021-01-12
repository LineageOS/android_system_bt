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

#include "hci/le_scanning_manager.h"

#include <cstdint>
#include <unordered_map>
#include <utility>

#include "common/bidi_queue.h"
#include "common/bind.h"
#include "grpc/grpc_event_queue.h"
#include "hci/facade/le_scanning_manager_facade.grpc.pb.h"
#include "hci/facade/le_scanning_manager_facade.h"
#include "hci/facade/le_scanning_manager_facade.pb.h"
#include "hci/le_report.h"
#include "os/log.h"
#include "packet/raw_builder.h"

namespace bluetooth {
namespace hci {
namespace facade {

using ::grpc::ServerAsyncResponseWriter;
using ::grpc::ServerAsyncWriter;
using ::grpc::ServerContext;
using ::grpc::ServerWriter;
using ::grpc::Status;

class LeScanningManagerFacadeService : public LeScanningManagerFacade::Service, ScanningCallback {
 public:
  LeScanningManagerFacadeService(LeScanningManager* le_scanning_manager, os::Handler* facade_handler)
      : le_scanning_manager_(le_scanning_manager), facade_handler_(facade_handler) {
    ASSERT(le_scanning_manager_ != nullptr);
    ASSERT(facade_handler_ != nullptr);
    le_scanning_manager_->RegisterScanningCallback(this);
  }

  ::grpc::Status StartScan(::grpc::ServerContext* context, const ::google::protobuf::Empty*,
                           ::grpc::ServerWriter<LeReportMsg>* writer) override {
    le_scanning_manager_->Scan(true);
    return pending_events_.RunLoop(context, writer);
  }

  ::grpc::Status StopScan(::grpc::ServerContext* context, const ::google::protobuf::Empty*,
                          ScanStoppedMsg* response) override {
    le_scanning_manager_->Scan(false);
    return ::grpc::Status::OK;
  }

  void OnScannerRegistered(const bluetooth::hci::Uuid app_uuid, ScannerId scanner_id, ScanningStatus status){};
  void OnScanResult(
      uint16_t event_type,
      uint8_t address_type,
      Address address,
      uint8_t primary_phy,
      uint8_t secondary_phy,
      uint8_t advertising_sid,
      int8_t tx_power,
      int8_t rssi,
      uint16_t periodic_advertising_interval,
      std::vector<GapData> advertising_data) {
    LeReportMsg le_report_msg;
    std::vector<LeExtendedAdvertisingReport> advertisements;
    LeExtendedAdvertisingReport le_extended_advertising_report;
    le_extended_advertising_report.address_type_ = (DirectAdvertisingAddressType)address_type;
    le_extended_advertising_report.address_ = address;
    le_extended_advertising_report.advertising_data_ = advertising_data;
    le_extended_advertising_report.rssi_ = rssi;
    advertisements.push_back(le_extended_advertising_report);

    auto builder = LeExtendedAdvertisingReportBuilder::Create(advertisements);
    std::vector<uint8_t> bytes;
    BitInserter bit_inserter(bytes);
    builder->Serialize(bit_inserter);
    le_report_msg.set_event(std::string(bytes.begin(), bytes.end()));
    pending_events_.OnIncomingEvent(std::move(le_report_msg));
  };
  void OnTrackAdvFoundLost(){};
  void OnBatchScanReports(int client_if, int status, int report_format, int num_records, std::vector<uint8_t> data){};
  void OnTimeout(){};

  LeScanningManager* le_scanning_manager_;
  os::Handler* facade_handler_;
  ::bluetooth::grpc::GrpcEventQueue<LeReportMsg> pending_events_{"LeReports"};
};

void LeScanningManagerFacadeModule::ListDependencies(ModuleList* list) {
  ::bluetooth::grpc::GrpcFacadeModule::ListDependencies(list);
  list->add<hci::LeScanningManager>();
}

void LeScanningManagerFacadeModule::Start() {
  ::bluetooth::grpc::GrpcFacadeModule::Start();
  service_ = new LeScanningManagerFacadeService(GetDependency<hci::LeScanningManager>(), GetHandler());
}

void LeScanningManagerFacadeModule::Stop() {
  delete service_;
  ::bluetooth::grpc::GrpcFacadeModule::Stop();
}

::grpc::Service* LeScanningManagerFacadeModule::GetService() const {
  return service_;
}

const ModuleFactory LeScanningManagerFacadeModule::Factory =
    ::bluetooth::ModuleFactory([]() { return new LeScanningManagerFacadeModule(); });

}  // namespace facade
}  // namespace hci
}  // namespace bluetooth
