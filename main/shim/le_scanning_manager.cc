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

class BleScannerInterfaceImpl : public BleScannerInterface {
 public:
  ~BleScannerInterfaceImpl() override{};

  /** Registers a scanner with the stack */
  void RegisterScanner(RegisterCallback) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  /** Unregister a scanner from the stack */
  void Unregister(int scanner_id) { LOG(INFO) << __func__ << " in shim layer"; }

  /** Start or stop LE device scanning */
  void Scan(bool start) { LOG(INFO) << __func__ << " in shim layer"; }

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
};

BleScannerInterfaceImpl* bt_le_scanner_instance = nullptr;

BleScannerInterface* bluetooth::shim::get_ble_scanner_instance() {
  if (bt_le_scanner_instance == nullptr) {
    bt_le_scanner_instance = new BleScannerInterfaceImpl();
  }
  return bt_le_scanner_instance;
}