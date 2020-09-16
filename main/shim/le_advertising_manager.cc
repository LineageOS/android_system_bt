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

#define LOG_TAG "bt_shim_advertiser"

#include "le_advertising_manager.h"

#include <hardware/bluetooth.h>
#include <hardware/bt_gatt.h>

#include <vector>
#include "gd/common/init_flags.h"
#include "gd/hci/acl_manager.h"
#include "gd/hci/controller.h"
#include "gd/hci/le_advertising_manager.h"
#include "gd/packet/packet_view.h"
#include "main/shim/entry.h"

#include "ble_advertiser.h"
#include "btif_common.h"
#include "btm_api.h"
#include "btu.h"

using bluetooth::hci::Address;
using bluetooth::hci::AddressType;
using bluetooth::hci::ErrorCode;
using bluetooth::hci::GapData;
using bluetooth::hci::OwnAddressType;
using std::vector;

class BleAdvertiserInterfaceImpl : public BleAdvertiserInterface,
                                   public bluetooth::hci::AdvertisingCallback {
 public:
  ~BleAdvertiserInterfaceImpl() override{};

  void Init() {
    // Register callback
    bluetooth::shim::GetAdvertising()->RegisterAdvertisingCallback(this);

    if (!bluetooth::common::InitFlags::GdSecurityEnabled()) {
      // Set private policy
      auto address = bluetooth::shim::GetController()->GetMacAddress();
      bluetooth::hci::AddressWithType address_with_type(
          address, bluetooth::hci::AddressType::PUBLIC_DEVICE_ADDRESS);
      bluetooth::crypto_toolbox::Octet16 irk = {};
      auto minimum_rotation_time = std::chrono::milliseconds(7 * 60 * 1000);
      auto maximum_rotation_time = std::chrono::milliseconds(15 * 60 * 1000);
      bluetooth::shim::GetAclManager()->SetPrivacyPolicyForInitiatorAddress(
          bluetooth::hci::LeAddressManager::AddressPolicy::USE_PUBLIC_ADDRESS,
          address_with_type, irk, minimum_rotation_time, maximum_rotation_time);
    }
  }

  // nobody use this function
  void RegisterAdvertiser(IdStatusCallback cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void Unregister(uint8_t advertiser_id) override {
    LOG(INFO) << __func__ << " in shim layer";
    bluetooth::shim::GetAdvertising()->RemoveAdvertiser(advertiser_id);
  }

  // only for PTS test
  void GetOwnAddress(uint8_t advertiser_id, GetAddressCallback cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void SetParameters(uint8_t advertiser_id, AdvertiseParameters params,
                     ParametersCallback cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void SetData(int advertiser_id, bool set_scan_rsp, vector<uint8_t> data,
               StatusCallback cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void Enable(uint8_t advertiser_id, bool enable, StatusCallback cb,
              uint16_t duration, uint8_t maxExtAdvEvents,
              StatusCallback timeout_cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  // nobody use this function
  void StartAdvertising(uint8_t advertiser_id, StatusCallback cb,
                        AdvertiseParameters params,
                        std::vector<uint8_t> advertise_data,
                        std::vector<uint8_t> scan_response_data, int timeout_s,
                        MultiAdvCb timeout_cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void StartAdvertisingSet(IdTxPowerStatusCallback cb,
                           AdvertiseParameters params,
                           std::vector<uint8_t> advertise_data,
                           std::vector<uint8_t> scan_response_data,
                           PeriodicAdvertisingParameters periodic_params,
                           std::vector<uint8_t> periodic_data,
                           uint16_t duration, uint8_t maxExtAdvEvents,
                           IdStatusCallback timeout_cb) override {
    LOG(INFO) << __func__ << " in shim layer";

    bluetooth::hci::ExtendedAdvertisingConfig config{};
    config.connectable = params.advertising_event_properties & 0x01;
    config.scannable = params.advertising_event_properties & 0x02;
    config.legacy_pdus = params.advertising_event_properties & 0x10;
    config.anonymous = params.advertising_event_properties & 0x20;
    config.include_tx_power = params.advertising_event_properties & 0x40;
    config.interval_min = params.min_interval;
    config.interval_max = params.max_interval;
    config.channel_map = params.channel_map;
    config.tx_power = params.tx_power;
    config.use_le_coded_phy = params.primary_advertising_phy == 0x03;
    config.secondary_advertising_phy =
        static_cast<bluetooth::hci::SecondaryPhyType>(
            params.secondary_advertising_phy);
    config.enable_scan_request_notifications =
        static_cast<bluetooth::hci::Enable>(
            params.scan_request_notification_enable);

    if (bluetooth::shim::BTM_BleLocalPrivacyEnabled()) {
      config.own_address_type = OwnAddressType::RANDOM_DEVICE_ADDRESS;
    } else {
      config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
    }

    if (!bluetooth::common::InitFlags::GdSecurityEnabled()) {
      // use public address for testing
      config.own_address_type = OwnAddressType::PUBLIC_DEVICE_ADDRESS;
    }

    size_t offset = 0;

    while (offset < advertise_data.size()) {
      GapData gap_data;
      uint8_t len = advertise_data[offset];
      auto begin = advertise_data.begin() + offset;
      auto end = begin + len + 1;  // 1 byte for len
      auto data_copy = std::make_shared<std::vector<uint8_t>>(begin, end);
      bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian> packet(
          data_copy);
      GapData::Parse(&gap_data, packet.begin());
      config.advertisement.push_back(gap_data);
      offset += len + 1;  // 1 byte for len
    }

    offset = 0;
    while (offset < scan_response_data.size()) {
      GapData gap_data;
      uint8_t len = scan_response_data[offset];
      auto begin = scan_response_data.begin() + offset;
      auto end = begin + len + 1;  // 1 byte for len
      auto data_copy = std::make_shared<std::vector<uint8_t>>(begin, end);
      bluetooth::packet::PacketView<bluetooth::packet::kLittleEndian> packet(
          data_copy);
      GapData::Parse(&gap_data, packet.begin());
      config.scan_response.push_back(gap_data);
      offset += len + 1;  // 1 byte for len
    }

    // TODO check advertising data size
    config.operation = bluetooth::hci::Operation::COMPLETE_ADVERTISEMENT;

    power_status_callback_ = cb;

    bluetooth::hci::AdvertiserId id =
        bluetooth::shim::GetAdvertising()->ExtendedCreateAdvertiser(
            config, scan_callback, set_terminated_callback,
            bluetooth::shim::GetGdShimHandler());

    LOG(INFO) << " CYDBG id" << (uint16_t)id;
  }

  void SetPeriodicAdvertisingParameters(
      int advertiser_id, PeriodicAdvertisingParameters periodic_params,
      StatusCallback cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void SetPeriodicAdvertisingData(int advertiser_id, std::vector<uint8_t> data,
                                  StatusCallback cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void SetPeriodicAdvertisingEnable(int advertiser_id, bool enable,
                                    StatusCallback cb) override {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void on_scan(Address address, AddressType address_type) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  void on_set_terminated(ErrorCode error_code, uint8_t, uint8_t) {
    LOG(INFO) << __func__ << " in shim layer";
  }

  const bluetooth::common::Callback<void(Address, AddressType)> scan_callback =
      bluetooth::common::Bind(&BleAdvertiserInterfaceImpl::on_scan,
                              bluetooth::common::Unretained(this));

  const bluetooth::common::Callback<void(ErrorCode, uint8_t, uint8_t)>
      set_terminated_callback = bluetooth::common::Bind(
          &BleAdvertiserInterfaceImpl::on_set_terminated,
          bluetooth::common::Unretained(this));

  // AdvertisingCallback
  void OnAdvertisingSetStarted(uint8_t advertiser_id, int8_t tx_power,
                               AdvertisingStatus status) override {
    do_in_jni_thread(FROM_HERE,
                     base::Bind(power_status_callback_, advertiser_id, tx_power,
                                (uint8_t)status));
  }

  void onAdvertisingEnabled(uint8_t advertiser_id, bool enable,
                            uint8_t status) {
    // TODO
  }

  IdTxPowerStatusCallback power_status_callback_;
};

BleAdvertiserInterfaceImpl* bt_le_advertiser_instance = nullptr;

BleAdvertiserInterface* bluetooth::shim::get_ble_advertiser_instance() {
  if (bt_le_advertiser_instance == nullptr) {
    bt_le_advertiser_instance = new BleAdvertiserInterfaceImpl();
  }
  return bt_le_advertiser_instance;
};

void bluetooth::shim::init_advertising_manager() {
  bt_le_advertiser_instance->Init();
}
