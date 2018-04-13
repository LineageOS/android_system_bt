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

#include "btif/include/btif_common.h"
#include "gd/hci/address.h"
#include "gd/hci/le_scanning_manager.h"
#include "gd/storage/device.h"
#include "gd/storage/le_device.h"
#include "gd/storage/storage_module.h"
#include "main/shim/entry.h"
#include "main/shim/helpers.h"
#include "main/shim/shim.h"

#include "advertise_data_parser.h"
#include "stack/btm/btm_int_types.h"

using bluetooth::ToRawAddress;
using bluetooth::ToGdAddress;

extern void btm_ble_process_adv_pkt_cont_for_inquiry(
    uint16_t event_type, uint8_t address_type, const RawAddress& raw_address,
    uint8_t primary_phy, uint8_t secondary_phy, uint8_t advertising_sid,
    int8_t tx_power, int8_t rssi, uint16_t periodic_adv_int,
    std::vector<uint8_t> advertising_data);

extern void btif_dm_update_ble_remote_properties(const RawAddress& bd_addr,
                                                 BD_NAME bd_name,
                                                 tBT_DEVICE_TYPE dev_type);

class BleScannerInterfaceImpl : public BleScannerInterface,
                                public bluetooth::hci::ScanningCallback {
 public:
  ~BleScannerInterfaceImpl() override{};

  void Init() {
    LOG_INFO("init BleScannerInterfaceImpl");
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
    init_address_cache();
  }

  /** Setup scan filter params */
  void ScanFilterParamSetup(
      uint8_t client_if, uint8_t action, uint8_t filter_index,
      std::unique_ptr<btgatt_filt_param_setup_t> filt_param,
      FilterParamSetupCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";

    auto apcf_action = static_cast<bluetooth::hci::ApcfAction>(action);
    bluetooth::hci::AdvertisingFilterParameter advertising_filter_parameter;

    if (filt_param != nullptr) {
      if (filt_param && filt_param->dely_mode == 1) {
        bluetooth::shim::GetScanning()->TrackAdvertiser(client_if);
      }
      advertising_filter_parameter.feature_selection = filt_param->feat_seln;
      advertising_filter_parameter.list_logic_type =
          filt_param->list_logic_type;
      advertising_filter_parameter.filter_logic_type =
          filt_param->filt_logic_type;
      advertising_filter_parameter.rssi_high_thresh =
          filt_param->rssi_high_thres;
      advertising_filter_parameter.delivery_mode =
          static_cast<bluetooth::hci::DeliveryMode>(filt_param->dely_mode);
      if (filt_param && filt_param->dely_mode == 1) {
        advertising_filter_parameter.onfound_timeout =
            filt_param->found_timeout;
        advertising_filter_parameter.onfound_timeout_cnt =
            filt_param->found_timeout_cnt;
        advertising_filter_parameter.rssi_low_thres =
            filt_param->rssi_low_thres;
        advertising_filter_parameter.onlost_timeout = filt_param->lost_timeout;
        advertising_filter_parameter.num_of_tracking_entries =
            filt_param->num_of_tracking_entries;
      }
    }

    bluetooth::shim::GetScanning()->ScanFilterParameterSetup(
        apcf_action, filter_index, advertising_filter_parameter);
    // TODO refactor callback mechanism
    do_in_jni_thread(FROM_HERE,
                     base::Bind(cb, 0, 0, btm_status_value(BTM_SUCCESS)));
  }

  /** Configure a scan filter condition  */
  void ScanFilterAdd(int filter_index, std::vector<ApcfCommand> filters,
                     FilterConfigCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";
    std::vector<bluetooth::hci::AdvertisingPacketContentFilterCommand>
        new_filters = {};
    for (size_t i = 0; i < filters.size(); i++) {
      bluetooth::hci::AdvertisingPacketContentFilterCommand command{};
      if (!parse_filter_command(command, filters[i])) {
        LOG_ERROR("invalid apcf command");
        return;
      }
      new_filters.push_back(command);
    }
    bluetooth::shim::GetScanning()->ScanFilterAdd(filter_index, new_filters);
    do_in_jni_thread(FROM_HERE,
                     base::Bind(cb, 0, 0, 0, btm_status_value(BTM_SUCCESS)));
  }

  /** Clear all scan filter conditions for specific filter index*/
  void ScanFilterClear(int filter_index, FilterConfigCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";
    // This function doesn't used in java layer
  }

  /** Enable / disable scan filter feature*/
  void ScanFilterEnable(bool enable, EnableCallback cb) {
    LOG(INFO) << __func__ << " in shim layer";
    bluetooth::shim::GetScanning()->ScanFilterEnable(enable);

    uint8_t action = enable ? 1 : 0;
    do_in_jni_thread(FROM_HERE,
                     base::Bind(cb, action, btm_status_value(BTM_SUCCESS)));
  }

  /** Sets the LE scan interval and window in units of N*0.625 msec */
  void SetScanParameters(int scan_phy, std::vector<uint32_t> scan_interval,
                         std::vector<uint32_t> scan_window,
                         Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
    // use active scan
    auto scan_type = static_cast<bluetooth::hci::LeScanType>(0x01);
    bluetooth::shim::GetScanning()->SetScanParameters(scan_type, scan_interval[0], scan_window[0]);
    do_in_jni_thread(FROM_HERE, base::Bind(cb, 0));
  }

  /* Configure the batchscan storage */
  void BatchscanConfigStorage(int client_if, int batch_scan_full_max,
                              int batch_scan_trunc_max,
                              int batch_scan_notify_threshold, Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
    bluetooth::shim::GetScanning()->BatchScanConifgStorage(
        batch_scan_full_max, batch_scan_trunc_max, batch_scan_notify_threshold,
        client_if);
    do_in_jni_thread(FROM_HERE, base::Bind(cb, btm_status_value(BTM_SUCCESS)));
  }

  /* Enable batchscan */
  virtual void BatchscanEnable(int scan_mode, int scan_interval,
                               int scan_window, int addr_type, int discard_rule,
                               Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
    auto batch_scan_mode =
        static_cast<bluetooth::hci::BatchScanMode>(scan_mode);
    auto batch_scan_discard_rule =
        static_cast<bluetooth::hci::BatchScanDiscardRule>(discard_rule);
    bluetooth::shim::GetScanning()->BatchScanEnable(
        batch_scan_mode, scan_window, scan_interval, batch_scan_discard_rule);
    do_in_jni_thread(FROM_HERE, base::Bind(cb, btm_status_value(BTM_SUCCESS)));
  }

  /* Disable batchscan */
  virtual void BatchscanDisable(Callback cb) {
    LOG(INFO) << __func__ << " in shim layer";
    bluetooth::shim::GetScanning()->BatchScanDisable();
    do_in_jni_thread(FROM_HERE, base::Bind(cb, btm_status_value(BTM_SUCCESS)));
  }

  /* Read out batchscan reports */
  void BatchscanReadReports(int client_if, int scan_mode) {
    LOG(INFO) << __func__ << " in shim layer";
    auto batch_scan_mode =
        static_cast<bluetooth::hci::BatchScanMode>(scan_mode);
    auto scanner_id = static_cast<bluetooth::hci::ScannerId>(client_if);
    bluetooth::shim::GetScanning()->BatchScanReadReport(scanner_id,
                                                        batch_scan_mode);
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
  }

  void OnScanResult(uint16_t event_type, uint8_t address_type,
                    bluetooth::hci::Address address, uint8_t primary_phy,
                    uint8_t secondary_phy, uint8_t advertising_sid,
                    int8_t tx_power, int8_t rssi,
                    uint16_t periodic_advertising_interval,
                    std::vector<uint8_t> advertising_data) {
    RawAddress raw_address = ToRawAddress(address);

    do_in_jni_thread(
        FROM_HERE,
        base::BindOnce(&BleScannerInterfaceImpl::handle_remote_properties,
                       base::Unretained(this), raw_address, address_type,
                       advertising_data));

    do_in_jni_thread(
        FROM_HERE,
        base::BindOnce(&ScanningCallbacks::OnScanResult,
                       base::Unretained(scanning_callbacks_), event_type,
                       address_type, raw_address, primary_phy, secondary_phy,
                       advertising_sid, tx_power, rssi,
                       periodic_advertising_interval, advertising_data));

    // TODO: Remove when StartInquiry in GD part implemented
    btm_ble_process_adv_pkt_cont_for_inquiry(
        event_type, address_type, raw_address, primary_phy, secondary_phy,
        advertising_sid, tx_power, rssi, periodic_advertising_interval,
        advertising_data);
  }

  void OnTrackAdvFoundLost(bluetooth::hci::AdvertisingFilterOnFoundOnLostInfo
                               on_found_on_lost_info) {
    AdvertisingTrackInfo track_info = {};
    RawAddress raw_address =
        ToRawAddress(on_found_on_lost_info.advertiser_address);
    track_info.advertiser_address = raw_address;
    track_info.advertiser_address_type =
        on_found_on_lost_info.advertiser_address_type;
    track_info.scanner_id = on_found_on_lost_info.scanner_id;
    track_info.filter_index = on_found_on_lost_info.filter_index;
    track_info.advertiser_state = on_found_on_lost_info.advertiser_state;
    track_info.advertiser_info_present =
        static_cast<uint8_t>(on_found_on_lost_info.advertiser_info_present);
    if (on_found_on_lost_info.advertiser_info_present ==
        bluetooth::hci::AdvtInfoPresent::ADVT_INFO_PRESENT) {
      track_info.tx_power = on_found_on_lost_info.tx_power;
      track_info.rssi = on_found_on_lost_info.rssi;
      track_info.time_stamp = on_found_on_lost_info.time_stamp;
      auto adv_data = on_found_on_lost_info.adv_packet;
      track_info.adv_packet_len = (uint8_t)adv_data.size();
      track_info.adv_packet.reserve(adv_data.size());
      track_info.adv_packet.insert(track_info.adv_packet.end(),
                                   adv_data.begin(), adv_data.end());
      auto scan_rsp_data = on_found_on_lost_info.scan_response;
      track_info.scan_response_len = (uint8_t)scan_rsp_data.size();
      track_info.scan_response.reserve(adv_data.size());
      track_info.scan_response.insert(track_info.scan_response.end(),
                                      scan_rsp_data.begin(),
                                      scan_rsp_data.end());
    }
    do_in_jni_thread(
        FROM_HERE,
        base::BindOnce(&ScanningCallbacks::OnTrackAdvFoundLost,
                       base::Unretained(scanning_callbacks_), track_info));
  }

  void OnBatchScanReports(int client_if, int status, int report_format,
                          int num_records, std::vector<uint8_t> data) {
    do_in_jni_thread(
        FROM_HERE,
        base::BindOnce(&ScanningCallbacks::OnBatchScanReports,
                       base::Unretained(scanning_callbacks_), client_if, status,
                       report_format, num_records, data));
  }

  void OnBatchScanThresholdCrossed(int client_if) {
    do_in_jni_thread(
        FROM_HERE,
        base::BindOnce(&ScanningCallbacks::OnBatchScanThresholdCrossed,
                       base::Unretained(scanning_callbacks_), client_if));
  }

  void OnTimeout() {}

  void OnFilterEnable(bluetooth::hci::Enable enable, uint8_t status){};

  void OnFilterParamSetup(uint8_t available_spaces,
                          bluetooth::hci::ApcfAction action, uint8_t status){};

  void OnFilterConfigCallback(bluetooth::hci::ApcfFilterType filter_type,
                              uint8_t available_spaces,
                              bluetooth::hci::ApcfAction action,
                              uint8_t status){};

  ScanningCallbacks* scanning_callbacks_;

 private:
  bool parse_filter_command(
      bluetooth::hci::AdvertisingPacketContentFilterCommand&
          advertising_packet_content_filter_command,
      ApcfCommand apcf_command) {
    advertising_packet_content_filter_command.filter_type =
        static_cast<bluetooth::hci::ApcfFilterType>(apcf_command.type);
    bluetooth::hci::Address address = ToGdAddress(apcf_command.address);
    advertising_packet_content_filter_command.address = address;
    advertising_packet_content_filter_command.application_address_type =
        static_cast<bluetooth::hci::ApcfApplicationAddressType>(
            apcf_command.addr_type);

    if (!apcf_command.uuid.IsEmpty()) {
      uint8_t uuid_len = apcf_command.uuid.GetShortestRepresentationSize();
      switch (uuid_len) {
        case bluetooth::Uuid::kNumBytes16: {
          advertising_packet_content_filter_command.uuid =
              bluetooth::hci::Uuid::From16Bit(apcf_command.uuid.As16Bit());
        } break;
        case bluetooth::Uuid::kNumBytes32: {
          advertising_packet_content_filter_command.uuid =
              bluetooth::hci::Uuid::From32Bit(apcf_command.uuid.As32Bit());
        } break;
        case bluetooth::Uuid::kNumBytes128: {
          advertising_packet_content_filter_command.uuid =
              bluetooth::hci::Uuid::From128BitBE(
                  apcf_command.uuid.To128BitBE());
        } break;
        default:
          LOG_WARN("illegal UUID length %d", (uint16_t)uuid_len);
          return false;
      }
    }

    if (!apcf_command.uuid_mask.IsEmpty()) {
      uint8_t uuid_len = apcf_command.uuid.GetShortestRepresentationSize();
      switch (uuid_len) {
        case bluetooth::Uuid::kNumBytes16: {
          advertising_packet_content_filter_command.uuid_mask =
              bluetooth::hci::Uuid::From16Bit(apcf_command.uuid_mask.As16Bit());
        } break;
        case bluetooth::Uuid::kNumBytes32: {
          advertising_packet_content_filter_command.uuid_mask =
              bluetooth::hci::Uuid::From32Bit(apcf_command.uuid_mask.As32Bit());
        } break;
        case bluetooth::Uuid::kNumBytes128: {
          advertising_packet_content_filter_command.uuid_mask =
              bluetooth::hci::Uuid::From128BitBE(
                  apcf_command.uuid_mask.To128BitBE());
        } break;
        default:
          LOG_WARN("illegal UUID length %d", (uint16_t)uuid_len);
          return false;
      }
    }

    advertising_packet_content_filter_command.name.assign(
        apcf_command.name.begin(), apcf_command.name.end());
    advertising_packet_content_filter_command.company = apcf_command.company;
    advertising_packet_content_filter_command.company_mask =
        apcf_command.company_mask;
    advertising_packet_content_filter_command.data.assign(
        apcf_command.data.begin(), apcf_command.data.end());
    advertising_packet_content_filter_command.data_mask.assign(
        apcf_command.data_mask.begin(), apcf_command.data_mask.end());
    return true;
  }

  void handle_remote_properties(RawAddress bd_addr, tBLE_ADDR_TYPE addr_type,
                                std::vector<uint8_t> advertising_data) {
    // skip anonymous advertisment
    if (addr_type == BLE_ADDR_ANONYMOUS) {
      return;
    }

    auto device_type = bluetooth::hci::DeviceType::LE;
    uint8_t flag_len;
    const uint8_t* p_flag = AdvertiseDataParser::GetFieldByType(
        advertising_data, BTM_BLE_AD_TYPE_FLAG, &flag_len);
    if (p_flag != NULL && flag_len != 0) {
      if ((BTM_BLE_BREDR_NOT_SPT & *p_flag) == 0) {
        device_type = bluetooth::hci::DeviceType::DUAL;
      }
    }

    uint8_t remote_name_len;
    const uint8_t* p_eir_remote_name = AdvertiseDataParser::GetFieldByType(
        advertising_data, BTM_EIR_COMPLETE_LOCAL_NAME_TYPE, &remote_name_len);

    if (p_eir_remote_name == NULL) {
      p_eir_remote_name = AdvertiseDataParser::GetFieldByType(
          advertising_data, BT_EIR_SHORTENED_LOCAL_NAME_TYPE, &remote_name_len);
    }

    // update device name
    if ((addr_type != BLE_ADDR_RANDOM) || (p_eir_remote_name)) {
      if (!find_address_cache(bd_addr)) {
        add_address_cache(bd_addr);

        if (p_eir_remote_name) {
          if (remote_name_len > BD_NAME_LEN + 1 ||
              (remote_name_len == BD_NAME_LEN + 1 &&
               p_eir_remote_name[BD_NAME_LEN] != '\0')) {
            LOG_INFO("%s dropping invalid packet - device name too long: %d",
                     __func__, remote_name_len);
            return;
          }

          bt_bdname_t bdname;
          memcpy(bdname.name, p_eir_remote_name, remote_name_len);
          if (remote_name_len < BD_NAME_LEN + 1)
            bdname.name[remote_name_len] = '\0';

          btif_dm_update_ble_remote_properties(bd_addr, bdname.name,
                                               device_type);
        }
      }
    }
    if (!bluetooth::shim::is_gd_stack_started_up()) {
      LOG_WARN("Gd stack is stopped, return");
      return;
    }
    auto* storage_module = bluetooth::shim::GetStorage();
    bluetooth::hci::Address address = ToGdAddress(bd_addr);

    // update device type
    auto mutation = storage_module->Modify();
    bluetooth::storage::Device device =
        storage_module->GetDeviceByLegacyKey(address);
    mutation.Add(device.SetDeviceType(device_type));
    mutation.Commit();

    // update address type
    auto mutation2 = storage_module->Modify();
    bluetooth::storage::LeDevice le_device = device.Le();
    mutation2.Add(
        le_device.SetAddressType((bluetooth::hci::AddressType)addr_type));
    mutation2.Commit();
  }

  void add_address_cache(const RawAddress& p_bda) {
    // Remove the oldest entries
    while (remote_bdaddr_cache_.size() >= remote_bdaddr_cache_max_size_) {
      const RawAddress& raw_address = remote_bdaddr_cache_ordered_.front();
      remote_bdaddr_cache_.erase(raw_address);
      remote_bdaddr_cache_ordered_.pop();
    }
    remote_bdaddr_cache_.insert(p_bda);
    remote_bdaddr_cache_ordered_.push(p_bda);
  }

  bool find_address_cache(const RawAddress& p_bda) {
    return (remote_bdaddr_cache_.find(p_bda) != remote_bdaddr_cache_.end());
  }

  void init_address_cache(void) {
    remote_bdaddr_cache_.clear();
    remote_bdaddr_cache_ordered_ = {};
  }

  // all access to this variable should be done on the jni thread
  std::set<RawAddress> remote_bdaddr_cache_;
  std::queue<RawAddress> remote_bdaddr_cache_ordered_;
  const size_t remote_bdaddr_cache_max_size_ = 1024;
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
