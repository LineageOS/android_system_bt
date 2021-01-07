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

#define LOG_TAG "bt_shim_scanner"

#include "le_scanning_manager.h"

#include <base/bind.h>
#include <base/threading/thread.h>
#include <hardware/bluetooth.h>
#include <stdio.h>
#include <unordered_set>

#include "btif_common.h"
#include "gd/hci/address.h"
#include "gd/hci/le_scanning_manager.h"
#include "main/shim/entry.h"

class BleScannerInterfaceImpl : public BleScannerInterface,
                                public bluetooth::hci::ScanningCallback {
 public:
  ~BleScannerInterfaceImpl() override{};

  void Init() {
    bluetooth::shim::GetScanning()->RegisterScanningCallback(this);
  }

  /** Registers a scanner with the stack */
  void RegisterScanner(const bluetooth::Uuid& uuid, RegisterCallback) {
    LOG(INFO) << __func__ << " in shim layer";
    auto app_uuid = bluetooth::hci::Uuid::From128BitBE(uuid.To128BitBE());
    bluetooth::shim::GetScanning()->RegisterScanner(app_uuid);
  }

  /** Unregister a scanner from the stack */
  void Unregister(int scanner_id) {
    LOG(INFO) << __func__ << " in shim layer, scanner_id:" << scanner_id;
    bluetooth::shim::GetScanning()->Unregister(scanner_id);
  }

  /** Start or stop LE device scanning */
  void Scan(bool start) {
    LOG(INFO) << __func__ << " in shim layer";
    bluetooth::shim::GetScanning()->Scan(start);
  }

  /** Setup scan filter params */
  void ScanFilterParamSetup(
      uint8_t client_if, uint8_t action, uint8_t filt_index,
      std::unique_ptr<btgatt_filt_param_setup_t> filt_param,
      FilterParamSetupCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /** Configure a scan filter condition  */
  void ScanFilterAdd(int filter_index, std::vector<ApcfCommand> filters,
                     FilterConfigCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /** Clear all scan filter conditions for specific filter index*/
  void ScanFilterClear(int filt_index, FilterConfigCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /** Enable / disable scan filter feature*/
  void ScanFilterEnable(bool enable, EnableCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /** Sets the LE scan interval and window in units of N*0.625 msec */
  void SetScanParameters(int scan_interval, int scan_window, Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /* Configure the batchscan storage */
  void BatchscanConfigStorage(int client_if, int batch_scan_full_max,
                              int batch_scan_trunc_max,
                              int batch_scan_notify_threshold, Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /* Enable batchscan */
  virtual void BatchscanEnable(int scan_mode, int scan_interval,
                               int scan_window, int addr_type, int discard_rule,
                               Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /* Disable batchscan */
  virtual void BatchscanDisable(Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /* Read out batchscan reports */
  void BatchscanReadReports(int client_if, int scan_mode) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void StartSync(uint8_t sid, RawAddress address, uint16_t skip,
                 uint16_t timeout, StartSyncCb start_cb, SyncReportCb report_cb,
                 SyncLostCb lost_cb) {
    LOG(INFO) << __func__ << " in shim layer";
    // This function doesn't implement in the old stack
  }

  void StopSync(uint16_t handle) {
    LOG(INFO) << __func__ << " in shim layer";
    // This function doesn't implement in the old stack
  }

  void RegisterCallbacks(ScanningCallbacks* callbacks) {
    LOG(INFO) << __func__ << " in shim layer";
    scanning_callbacks_ = callbacks;
  }

  void OnScannerRegistered(const bluetooth::hci::Uuid app_uuid,
                           bluetooth::hci::ScannerId scanner_id,
                           ScanningStatus status) {
    auto uuid = bluetooth::Uuid::From128BitBE(app_uuid.To128BitBE());
    do_in_jni_thread(FROM_HERE,
                     base::Bind(&ScanningCallbacks::OnScannerRegistered,
                                base::Unretained(scanning_callbacks_), uuid,
                                scanner_id, status));
  };

  void OnScanResult(uint16_t event_type, uint8_t address_type,
                    bluetooth::hci::Address address, uint8_t primary_phy,
                    uint8_t secondary_phy, uint8_t advertising_sid,
                    int8_t tx_power, int8_t rssi,
                    uint16_t periodic_advertising_interval,
                    std::vector<bluetooth::hci::GapData> advertising_data) {
    RawAddress raw_address;
    RawAddress::FromString(address.ToString(), raw_address);
    std::unique_ptr<RawAddress> raw_address_ptr(new RawAddress(raw_address));

    std::vector<uint8_t> adv_data = {};
    for (auto gap_data : advertising_data) {
      gap_data.size();
      adv_data.push_back((uint8_t)gap_data.size() - 1);
      adv_data.push_back((uint8_t)gap_data.data_type_);
      adv_data.insert(adv_data.end(), gap_data.data_.begin(),
                      gap_data.data_.end());
    }

    do_in_jni_thread(
        FROM_HERE,
        base::BindOnce(&ScanningCallbacks::OnScanResult,
                       base::Unretained(scanning_callbacks_), event_type,
                       address_type, raw_address_ptr.get(), primary_phy,
                       secondary_phy, advertising_sid, tx_power, rssi,
                       periodic_advertising_interval, adv_data));
  };

  void OnTrackAdvFoundLost(){};

  void OnBatchScanReports(int client_if, int status, int report_format,
                          int num_records, std::vector<uint8_t> data){};

  ScanningCallbacks* scanning_callbacks_;
};

BleScannerInterfaceImpl* bt_le_scanner_instance = nullptr;

BleScannerInterface* bluetooth::shim::get_ble_scanner_instance() {
  if (bt_le_scanner_instance == nullptr) {
    bt_le_scanner_instance = new BleScannerInterfaceImpl();
  }
  return bt_le_scanner_instance;
}

void bluetooth::shim::init_scanning_manager() {
  bt_le_scanner_instance->Init();
}