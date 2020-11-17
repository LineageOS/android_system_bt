/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef ANDROID_INCLUDE_BLE_ADVERTISER_H
#define ANDROID_INCLUDE_BLE_ADVERTISER_H

#include <base/callback_forward.h>
#include <stdint.h>
#include <vector>
#include "bt_common_types.h"
#include "bt_gatt_types.h"

struct AdvertiseParameters {
  uint16_t advertising_event_properties;
  uint32_t min_interval;
  uint32_t max_interval;
  uint8_t channel_map;
  int8_t tx_power;
  uint8_t primary_advertising_phy;
  uint8_t secondary_advertising_phy;
  uint8_t scan_request_notification_enable;
};

struct CreateBIGParameters {
  uint8_t adv_handle;
  uint8_t num_bis;
  uint32_t sdu_int;
  uint16_t max_sdu;
  uint16_t max_transport_latency;
  uint8_t rtn;
  uint8_t phy;
  uint8_t packing;
  uint8_t framing;
  uint8_t encryption;
  std::vector<uint8_t> broadcast_code;
};

struct PeriodicAdvertisingParameters {
  uint8_t enable;
  uint16_t min_interval;
  uint16_t max_interval;
  uint16_t periodic_advertising_properties;
};

class BleAdvertiserInterface {
 public:
  virtual ~BleAdvertiserInterface() = default;

  /** Callback invoked when multi-adv operation has completed */
  using StatusCallback = base::Callback<void(uint8_t /* status */)>;
  using IdStatusCallback =
      base::Callback<void(uint8_t /* advertiser_id */, uint8_t /* status */)>;
  using IdTxPowerStatusCallback =
      base::Callback<void(uint8_t /* advertiser_id */, int8_t /* tx_power */,
                          uint8_t /* status */)>;
  using ParametersCallback =
      base::Callback<void(uint8_t /* status */, int8_t /* tx_power */)>;
  using CreateBIGCallback = base::Callback<void(uint8_t /*adv_inst_id*/,
      uint8_t /*status*/, uint8_t /*big_handle*/, uint32_t /*big_sync_delay*/,
      uint32_t /*transport_latency_big*/, uint8_t /*phy*/, uint8_t /*nse*/,
      uint8_t /*bn*/, uint8_t /*pto*/, uint8_t /*irc*/, uint16_t /*max_pdu*/,
      uint16_t /*iso_int*/, uint8_t /*num_bis*/,
      std::vector<uint16_t> /*conn_handle_list*/)>;
  using TerminateBIGCallback =
      base::Callback<void(uint8_t /* status */, uint8_t /* advertiser_id */,
      uint8_t /* big_handle */, uint8_t /* reason */)>;
  /** Registers an advertiser with the stack */
  virtual void RegisterAdvertiser(IdStatusCallback) = 0;

  using GetAddressCallback =
      base::Callback<void(uint8_t /* address_type*/, RawAddress /*address*/)>;
  virtual void GetOwnAddress(uint8_t advertiser_id, GetAddressCallback cb) = 0;

  /* Set the parameters as per spec, user manual specified values */
  virtual void SetParameters(uint8_t advertiser_id, AdvertiseParameters params,
                             ParametersCallback cb) = 0;

  /* Setup the data */
  virtual void SetData(int advertiser_id, bool set_scan_rsp,
                       std::vector<uint8_t> data, StatusCallback cb) = 0;

  /* Enable the advertising instance */
  virtual void Enable(uint8_t advertiser_id, bool enable, StatusCallback cb,
                      uint16_t duration, uint8_t maxExtAdvEvents,
                      StatusCallback timeout_cb) = 0;

  /*  Unregisters an advertiser */
  virtual void Unregister(uint8_t advertiser_id) = 0;

  virtual void StartAdvertising(uint8_t advertiser_id, StatusCallback cb,
                                AdvertiseParameters params,
                                std::vector<uint8_t> advertise_data,
                                std::vector<uint8_t> scan_response_data,
                                int timeout_s, StatusCallback timeout_cb) = 0;

  /** Start the advertising set. This include registering, setting all
   * parameters and data, and enabling it. |register_cb| is called when the set
   * is advertising. |timeout_cb| is called when the timeout_s have passed */
  virtual void StartAdvertisingSet(
      IdTxPowerStatusCallback register_cb, AdvertiseParameters params,
      std::vector<uint8_t> advertise_data,
      std::vector<uint8_t> scan_response_data,
      PeriodicAdvertisingParameters periodic_params,
      std::vector<uint8_t> periodic_data, uint16_t duration,
      uint8_t maxExtAdvEvents, IdStatusCallback timeout_cb) = 0;

  virtual void SetPeriodicAdvertisingParameters(
      int advertiser_id, PeriodicAdvertisingParameters parameters,
      StatusCallback cb) = 0;

  virtual void SetPeriodicAdvertisingData(int advertiser_id,
                                          std::vector<uint8_t> data,
                                          StatusCallback cb) = 0;

  virtual void CreateBIG(
      int advertiser_id, CreateBIGParameters create_big_params,
      CreateBIGCallback cb) = 0;

  virtual void TerminateBIG(
      int advertiser_id, int big_handle, int reason,
      TerminateBIGCallback cb) = 0;

  virtual void SetPeriodicAdvertisingEnable(int advertiser_id, bool enable,
                                            StatusCallback cb) = 0;
};

#endif /* ANDROID_INCLUDE_BLE_ADVERTISER_H */
