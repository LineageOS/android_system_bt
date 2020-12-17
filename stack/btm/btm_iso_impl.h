/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#include <map>
#include <memory>
#include <set>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "bt_types.h"
#include "btm_iso_api.h"
#include "btu.h"
#include "common/time_util.h"
#include "device/include/controller.h"
#include "osi/include/log.h"

namespace bluetooth {
namespace hci {
namespace iso_manager {
static constexpr uint8_t kIsoDataInTsBtHdrOffset = 0x0C;
static constexpr uint8_t kIsoHeaderWithTsLen = 12;
static constexpr uint8_t kIsoHeaderWithoutTsLen = 8;

static constexpr uint8_t kStateFlagsNone = 0x00;
static constexpr uint8_t kStateFlagIsConnected = 0x01;
static constexpr uint8_t kStateFlagHasDataPathSet = 0x02;
static constexpr uint8_t kStateFlagIsBroadcast = 0x04;

struct iso_sync_info {
  uint32_t first_sync_ts;
  uint16_t seq_nb;
};

struct iso_base {
  union {
    uint8_t cig_id;
    uint8_t big_handle;
  };

  struct iso_sync_info sync_info;
  uint8_t state_flags;
  uint32_t sdu_itv;
};

typedef iso_base iso_cis;
typedef iso_base iso_bis;

struct iso_impl {
  iso_impl() {
    iso_credits_ = controller_get_interface()->get_iso_buffer_count();
    iso_buffer_size_ = controller_get_interface()->get_iso_data_size();
  }

  ~iso_impl() {}

  void handle_register_cis_callbacks(CigCallbacks* callbacks) {
    LOG_ASSERT(callbacks != nullptr) << "Invalid CIG callbacks";
    cig_callbacks_ = callbacks;
  }

  void handle_register_big_callbacks(BigCallbacks* callbacks) {
    LOG_ASSERT(callbacks != nullptr) << "Invalid BIG callbacks";
    big_callbacks_ = callbacks;
  }

  void on_set_cig_params(uint8_t cig_id, uint32_t sdu_itv_mtos, uint8_t* stream,
                         uint16_t len) {
    uint8_t cis_cnt;
    uint16_t conn_handle;
    cig_create_cmpl_evt evt;

    LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";
    LOG_ASSERT(len >= 3) << "Invalid packet length.";

    STREAM_TO_UINT8(evt.status, stream);
    STREAM_TO_UINT8(evt.cig_id, stream);
    STREAM_TO_UINT8(cis_cnt, stream);

    uint8_t evt_code = IsCigKnown(cig_id) ? kIsoEventCigOnReconfigureCmpl
                                          : kIsoEventCigOnCreateCmpl;

    if (evt.status == HCI_SUCCESS) {
      LOG_ASSERT(len >= (3) + (cis_cnt * sizeof(uint16_t)))
          << "Invalid CIS count.";

      /* Remove entries for the reconfigured CIG */
      if (evt_code == kIsoEventCigOnReconfigureCmpl) {
        auto cis_it = conn_hdl_to_cis_map_.cbegin();
        while (cis_it != conn_hdl_to_cis_map_.cend()) {
          if (cis_it->second->cig_id == evt.cig_id)
            cis_it = conn_hdl_to_cis_map_.erase(cis_it);
          else
            ++cis_it;
        }
      }

      evt.conn_handles.reserve(cis_cnt);
      for (int i = 0; i < cis_cnt; i++) {
        STREAM_TO_UINT16(conn_handle, stream);

        evt.conn_handles.push_back(conn_handle);
        conn_hdl_to_cis_map_[conn_handle] = std::unique_ptr<iso_cis>(
            new iso_cis({.sync_info = {.first_sync_ts = 0, .seq_nb = 0},
                         .cig_id = cig_id,
                         .state_flags = kStateFlagsNone,
                         .sdu_itv = sdu_itv_mtos}));
      }
    }

    cig_callbacks_->OnCigEvent(evt_code, &evt);
  }

  void create_cig(uint8_t cig_id,
                  struct iso_manager::cig_create_params cig_params) {
    LOG_ASSERT(!IsCigKnown(cig_id)) << "Invalid cig - already exists.";

    btsnd_hcic_set_cig_params(
        cig_id, cig_params.sdu_itv_mtos, cig_params.sdu_itv_stom,
        cig_params.sca, cig_params.packing, cig_params.framing,
        cig_params.max_trans_lat_stom, cig_params.max_trans_lat_mtos,
        cig_params.cis_cfgs.size(), cig_params.cis_cfgs.data(),
        base::BindOnce(&iso_impl::on_set_cig_params, base::Unretained(this),
                       cig_id, cig_params.sdu_itv_mtos));
  }

  void reconfigure_cig(uint8_t cig_id,
                       struct iso_manager::cig_create_params cig_params) {
    LOG_ASSERT(IsCigKnown(cig_id)) << "No such cig";

    btsnd_hcic_set_cig_params(
        cig_id, cig_params.sdu_itv_mtos, cig_params.sdu_itv_stom,
        cig_params.sca, cig_params.packing, cig_params.framing,
        cig_params.max_trans_lat_stom, cig_params.max_trans_lat_mtos,
        cig_params.cis_cfgs.size(), cig_params.cis_cfgs.data(),
        base::BindOnce(&iso_impl::on_set_cig_params, base::Unretained(this),
                       cig_id, cig_params.sdu_itv_mtos));
  }

  void on_remove_cig(uint8_t* stream, uint16_t len) {
    cig_remove_cmpl_evt evt;

    LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";
    LOG_ASSERT(len == 2) << "Invalid packet length.";

    STREAM_TO_UINT8(evt.status, stream);
    STREAM_TO_UINT8(evt.cig_id, stream);

    if (evt.status == HCI_SUCCESS) {
      auto cis_it = conn_hdl_to_cis_map_.cbegin();
      while (cis_it != conn_hdl_to_cis_map_.cend()) {
        if (cis_it->second->cig_id == evt.cig_id)
          cis_it = conn_hdl_to_cis_map_.erase(cis_it);
        else
          ++cis_it;
      }
    }

    cig_callbacks_->OnCigEvent(kIsoEventCigOnRemoveCmpl, &evt);
  }

  void remove_cig(uint8_t cig_id) {
    LOG_ASSERT(IsCigKnown(cig_id)) << "No such cig";

    btsnd_hcic_remove_cig(cig_id, base::BindOnce(&iso_impl::on_remove_cig,
                                                 base::Unretained(this)));
  }

  void on_status_establish_cis(
      struct iso_manager::cis_establish_params conn_params, uint8_t* stream,
      uint16_t len) {
    uint8_t status;

    LOG_ASSERT(len == 2) << "Invalid packet length: " << len;

    STREAM_TO_UINT16(status, stream);
    if (status == HCI_SUCCESS) {
      /* Wait for connection established event */
      return;
    }

    for (auto cis : conn_params.conn_pairs) {
      cis_establish_cmpl_evt evt;

      evt.status = status;
      evt.cis_conn_hdl = cis.cis_conn_handle;
      evt.cig_id = 0xFF;
      cig_callbacks_->OnCisEvent(kIsoEventCisEstablishCmpl, &evt);
    }
  }

  void establish_cis(struct iso_manager::cis_establish_params conn_params) {
    for (auto& el : conn_params.conn_pairs) {
      auto cis = GetCisIfKnown(el.cis_conn_handle);
      LOG_ASSERT(cis) << "No such cis";
      LOG_ASSERT(!(cis->state_flags & kStateFlagIsConnected))
          << "Already connected";
    }
    btsnd_hcic_create_cis(conn_params.conn_pairs.size(),
                          conn_params.conn_pairs.data(),
                          base::BindOnce(&iso_impl::on_status_establish_cis,
                                         base::Unretained(this), conn_params));
  }

  void disconnect_cis(uint16_t cis_handle, uint8_t reason) {
    auto cis = GetCisIfKnown(cis_handle);
    LOG_ASSERT(cis) << "No such cis";
    LOG_ASSERT(cis->state_flags & kStateFlagIsConnected) << "Not connected";
    bluetooth::legacy::hci::GetInterface().Disconnect(
        cis_handle, static_cast<tHCI_STATUS>(reason));
  }

  void on_setup_iso_data_path(uint8_t* stream, uint16_t len) {
    uint8_t status;
    uint16_t conn_handle;

    STREAM_TO_UINT8(status, stream);
    STREAM_TO_UINT16(conn_handle, stream);

    iso_base* iso = GetIsoIfKnown(conn_handle);
    LOG_ASSERT(iso != nullptr) << "Invalid connection handle: " << +conn_handle;

    if (status == HCI_SUCCESS) iso->state_flags |= kStateFlagHasDataPathSet;
    if (iso->state_flags & kStateFlagIsBroadcast) {
      LOG_ASSERT(big_callbacks_ != nullptr) << "Invalid BIG callbacks";
      big_callbacks_->OnSetupIsoDataPath(status, conn_handle, iso->big_handle);
    } else {
      LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";
      cig_callbacks_->OnSetupIsoDataPath(status, conn_handle, iso->cig_id);
    }
  }

  void setup_iso_data_path(
      uint16_t conn_handle,
      struct iso_manager::iso_data_path_params path_params) {
    iso_base* iso = GetIsoIfKnown(conn_handle);
    LOG_ASSERT(iso != nullptr) << "No such iso connection: " << +conn_handle;

    if (!(iso->state_flags & kStateFlagIsBroadcast)) {
      LOG_ASSERT(iso->state_flags & kStateFlagIsConnected)
          << "CIS not established";
    }

    btsnd_hcic_setup_iso_data_path(
        conn_handle, path_params.data_path_dir, path_params.data_path_id,
        path_params.codec_id_format, path_params.codec_id_company,
        path_params.codec_id_vendor, path_params.controller_delay,
        std::move(path_params.codec_conf),
        base::BindOnce(&iso_impl::on_setup_iso_data_path,
                       base::Unretained(this)));
  }

  void on_remove_iso_data_path(uint8_t* stream, uint16_t len) {
    uint8_t status;
    uint16_t conn_handle;

    STREAM_TO_UINT8(status, stream);
    STREAM_TO_UINT16(conn_handle, stream);

    iso_base* iso = GetIsoIfKnown(conn_handle);
    LOG_ASSERT(iso != nullptr) << "Invalid connection handle: " << +conn_handle;

    if (status == HCI_SUCCESS) iso->state_flags &= ~kStateFlagHasDataPathSet;

    if (iso->state_flags & kStateFlagIsBroadcast) {
      LOG_ASSERT(big_callbacks_ != nullptr) << "Invalid BIG callbacks";
      big_callbacks_->OnRemoveIsoDataPath(status, conn_handle, iso->big_handle);
    } else {
      LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";
      cig_callbacks_->OnRemoveIsoDataPath(status, conn_handle, iso->cig_id);
    }
  }

  void remove_iso_data_path(uint16_t iso_handle, uint8_t data_path_dir) {
    iso_base* iso = GetIsoIfKnown(iso_handle);
    LOG_ASSERT(iso != nullptr) << "No such iso connection";
    LOG_ASSERT((iso->state_flags & kStateFlagHasDataPathSet) ==
               kStateFlagHasDataPathSet)
        << "Data path not set";

    btsnd_hcic_remove_iso_data_path(
        iso_handle, data_path_dir,
        base::BindOnce(&iso_impl::on_remove_iso_data_path,
                       base::Unretained(this)));
  }

  void on_iso_link_quality_read(uint8_t* stream, uint16_t len) {
    uint8_t status;
    uint16_t conn_handle;
    uint32_t txUnackedPackets;
    uint32_t txFlushedPackets;
    uint32_t txLastSubeventPackets;
    uint32_t retransmittedPackets;
    uint32_t crcErrorPackets;
    uint32_t rxUnreceivedPackets;
    uint32_t duplicatePackets;

    STREAM_TO_UINT8(status, stream);
    if (status != HCI_SUCCESS) {
      LOG(ERROR) << "Failed to Read ISO Link Quality, status: "
                 << loghex(status);
      return;
    }

    STREAM_TO_UINT16(conn_handle, stream);

    iso_base* iso = GetIsoIfKnown(conn_handle);
    LOG_ASSERT(iso != nullptr) << "Invalid connection handle: " << +conn_handle;

    STREAM_TO_UINT32(txUnackedPackets, stream);
    STREAM_TO_UINT32(txFlushedPackets, stream);
    STREAM_TO_UINT32(txLastSubeventPackets, stream);
    STREAM_TO_UINT32(retransmittedPackets, stream);
    STREAM_TO_UINT32(crcErrorPackets, stream);
    STREAM_TO_UINT32(rxUnreceivedPackets, stream);
    STREAM_TO_UINT32(duplicatePackets, stream);

    LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";
    cig_callbacks_->OnIsoLinkQualityRead(
        conn_handle, iso->cig_id, txUnackedPackets, txFlushedPackets,
        txLastSubeventPackets, retransmittedPackets, crcErrorPackets,
        rxUnreceivedPackets, duplicatePackets);
  }

  void read_iso_link_quality(uint16_t iso_handle) {
    iso_base* iso = GetIsoIfKnown(iso_handle);
    LOG_ASSERT(iso != nullptr) << "No such iso connection";

    btsnd_hcic_read_iso_link_quality(
        iso_handle, base::BindOnce(&iso_impl::on_iso_link_quality_read,
                                   base::Unretained(this)));
  }

  BT_HDR* prepare_ts_hci_packet(uint16_t iso_handle, uint32_t ts,
                                uint16_t seq_nb, uint16_t data_len) {
    /* Add 2 for packet seq., 2 for length, 4 for the timestamp */
    uint16_t iso_data_load_len = data_len + 8;

    /* Add 2 for handle, 2 for length */
    uint16_t iso_full_len = iso_data_load_len + 4;
    BT_HDR* packet = (BT_HDR*)osi_malloc(iso_full_len + sizeof(BT_HDR));
    packet->len = iso_full_len;
    packet->offset = 0;
    packet->event = MSG_STACK_TO_HC_HCI_ISO;
    packet->layer_specific = 0;

    uint8_t* packet_data = packet->data;
    UINT16_TO_STREAM(packet_data, iso_handle);
    UINT16_TO_STREAM(packet_data, iso_data_load_len);

    packet->layer_specific |= BT_ISO_HDR_CONTAINS_TS;
    UINT32_TO_STREAM(packet_data, ts);

    UINT16_TO_STREAM(packet_data, seq_nb);
    UINT16_TO_STREAM(packet_data, data_len);

    return packet;
  }

  void send_iso_data_hci_packet(BT_HDR* packet) {
    bte_main_hci_send(packet, MSG_STACK_TO_HC_HCI_ISO | 0x0001);
  }

  void send_iso_data(uint16_t iso_handle, const uint8_t* data,
                     uint16_t data_len) {
    iso_base* iso = GetIsoIfKnown(iso_handle);
    LOG_ASSERT(iso != nullptr)
        << "No such iso connection handle: " << +iso_handle;

    if (!(iso->state_flags & kStateFlagIsBroadcast)) {
      LOG_ASSERT(iso->state_flags & kStateFlagIsConnected)
          << "CIS not established";
    }
    LOG_ASSERT(iso->state_flags & kStateFlagHasDataPathSet)
        << "Data path not set for handle: " << +iso_handle;

    /* Calculate sequence number for the ISO data packet.
     * It should be incremented by 1 every SDU Interval.
     */
    uint32_t ts = bluetooth::common::time_get_os_boottime_us();
    iso->sync_info.seq_nb = (ts - iso->sync_info.first_sync_ts) / iso->sdu_itv;

    if (iso_credits_ == 0 || data_len > iso_buffer_size_) {
      LOG(WARNING) << __func__ << ", dropping ISO packet, len: "
                   << static_cast<int>(data_len)
                   << ", iso credits: " << static_cast<int>(iso_credits_);
      return;
    }

    iso_credits_--;

    BT_HDR* packet =
        prepare_ts_hci_packet(iso_handle, ts, iso->sync_info.seq_nb, data_len);
    memcpy(packet->data + kIsoDataInTsBtHdrOffset, data, data_len);
    send_iso_data_hci_packet(packet);
  }

  void process_cis_est_pkt(uint8_t len, uint8_t* data) {
    cis_establish_cmpl_evt evt;

    LOG_ASSERT(len == 28) << "Invalid packet length";
    LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";

    STREAM_TO_UINT8(evt.status, data);
    STREAM_TO_UINT16(evt.cis_conn_hdl, data);

    auto cis = GetCisIfKnown(evt.cis_conn_hdl);
    LOG_ASSERT(cis != nullptr) << "No such cis";

    cis->sync_info.first_sync_ts = bluetooth::common::time_get_os_boottime_us();

    STREAM_TO_UINT24(evt.cig_sync_delay, data);
    STREAM_TO_UINT24(evt.cis_sync_delay, data);
    STREAM_TO_UINT24(evt.trans_lat_mtos, data);
    STREAM_TO_UINT24(evt.trans_lat_stom, data);
    STREAM_TO_UINT8(evt.phy_mtos, data);
    STREAM_TO_UINT8(evt.phy_stom, data);
    STREAM_TO_UINT8(evt.nse, data);
    STREAM_TO_UINT8(evt.bn_mtos, data);
    STREAM_TO_UINT8(evt.bn_stom, data);
    STREAM_TO_UINT8(evt.ft_mtos, data);
    STREAM_TO_UINT8(evt.ft_stom, data);
    STREAM_TO_UINT16(evt.max_pdu_mtos, data);
    STREAM_TO_UINT16(evt.max_pdu_stom, data);
    STREAM_TO_UINT16(evt.iso_itv, data);

    if (evt.status == HCI_SUCCESS) cis->state_flags |= kStateFlagIsConnected;

    evt.cig_id = cis->cig_id;
    cig_callbacks_->OnCisEvent(kIsoEventCisEstablishCmpl, &evt);
  }

  void disconnection_complete(uint16_t handle, uint8_t reason) {
    /* Check if this is an ISO handle */
    auto cis = GetCisIfKnown(handle);
    if (cis == nullptr) return;

    LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";

    LOG_INFO("%s flags: %d", __func__, +cis->state_flags);
    if (cis->state_flags & kStateFlagIsConnected) {
      cis_disconnected_evt evt = {
          .reason = reason,
          .cis_conn_hdl = handle,
          .cig_id = cis->cig_id,
      };

      cig_callbacks_->OnCisEvent(kIsoEventCisDisconnected, &evt);
      cis->state_flags &= ~kStateFlagIsConnected;
      /* Data path is considered still valid, but can be reconfigured only once
       * CIS is reestablished.
       */
    }
  }

  void handle_num_completed_pkts(uint8_t* p, uint8_t evt_len) {
    uint8_t num_handles;

    STREAM_TO_UINT8(num_handles, p);

    LOG_ASSERT(evt_len == num_handles * 4 + 1);

    for (int i = 0; i < num_handles; i++) {
      uint16_t handle, num_sent;

      STREAM_TO_UINT16(handle, p);
      STREAM_TO_UINT16(num_sent, p);

      if ((conn_hdl_to_cis_map_.find(handle) == conn_hdl_to_cis_map_.end()) &&
          (conn_hdl_to_bis_map_.find(handle) == conn_hdl_to_bis_map_.end()))
        continue;

      iso_credits_ += num_sent;
    }
  }

  void process_create_big_cmpl_pkt(uint8_t len, uint8_t* data) {
    struct big_create_cmpl_evt evt;

    LOG_ASSERT(len >= 18) << "Invalid packet length";
    LOG_ASSERT(big_callbacks_ != nullptr) << "Invalid BIG callbacks";

    STREAM_TO_UINT8(evt.status, data);
    STREAM_TO_UINT8(evt.big_id, data);
    STREAM_TO_UINT24(evt.big_sync_delay, data);
    STREAM_TO_UINT24(evt.transport_latency_big, data);
    STREAM_TO_UINT8(evt.phy, data);
    STREAM_TO_UINT8(evt.nse, data);
    STREAM_TO_UINT8(evt.bn, data);
    STREAM_TO_UINT8(evt.pto, data);
    STREAM_TO_UINT8(evt.irc, data);
    STREAM_TO_UINT16(evt.max_pdu, data);
    STREAM_TO_UINT16(evt.iso_interval, data);

    uint8_t num_bis;
    STREAM_TO_UINT8(num_bis, data);

    LOG_ASSERT(num_bis != 0) << "Invalid bis count";
    LOG_ASSERT(len == (18 + num_bis * sizeof(uint16_t)))
        << "Invalid packet length";

    uint32_t ts = bluetooth::common::time_get_os_boottime_us();
    for (auto i = 0; i < num_bis; ++i) {
      uint16_t conn_handle;
      STREAM_TO_UINT16(conn_handle, data);
      evt.conn_handles.push_back(conn_handle);
      LOG_INFO(" received BIS conn_hdl %d", +conn_handle);

      if (evt.status == HCI_SUCCESS) {
        conn_hdl_to_bis_map_[conn_handle] = std::unique_ptr<iso_bis>(
            new iso_bis({.sync_info = {.first_sync_ts = ts, .seq_nb = 0},
                         .big_handle = evt.big_id,
                         .state_flags = kStateFlagIsBroadcast,
                         .sdu_itv = last_big_create_req_sdu_itv_}));
      }
    }

    big_callbacks_->OnBigEvent(kIsoEventBigOnCreateCmpl, &evt);
  }

  void process_terminate_big_cmpl_pkt(uint8_t len, uint8_t* data) {
    struct big_terminate_cmpl_evt evt;

    LOG_ASSERT(len == 2) << "Invalid packet length";
    LOG_ASSERT(big_callbacks_ != nullptr) << "Invalid BIG callbacks";

    STREAM_TO_UINT8(evt.big_id, data);
    STREAM_TO_UINT8(evt.reason, data);

    bool is_known_handle = false;
    auto bis_it = conn_hdl_to_bis_map_.cbegin();
    while (bis_it != conn_hdl_to_bis_map_.cend()) {
      if (bis_it->second->big_handle == evt.big_id) {
        bis_it = conn_hdl_to_bis_map_.erase(bis_it);
        is_known_handle = true;
      } else {
        ++bis_it;
      }
    }

    LOG_ASSERT(is_known_handle) << "No such big";
    big_callbacks_->OnBigEvent(kIsoEventBigOnTerminateCmpl, &evt);
  }

  void create_big(uint8_t big_id, struct big_create_params big_params) {
    LOG_ASSERT(!IsBigKnown(big_id)) << "Invalid big - already exists";

    last_big_create_req_sdu_itv_ = big_params.sdu_itv;
    btsnd_hcic_create_big(
        big_id, big_params.adv_handle, big_params.num_bis, big_params.sdu_itv,
        big_params.max_sdu_size, big_params.max_transport_latency,
        big_params.rtn, big_params.phy, big_params.packing, big_params.framing,
        big_params.enc, big_params.enc_code);
  }

  void terminate_big(uint8_t big_id, uint8_t reason) {
    LOG_ASSERT(IsBigKnown(big_id)) << "No such big";

    btsnd_hcic_term_big(big_id, reason);
  }

  void on_iso_event(uint8_t code, uint8_t* packet, uint16_t packet_len) {
    switch (code) {
      case HCI_BLE_CIS_EST_EVT:
        process_cis_est_pkt(packet_len, packet);
        break;
      case HCI_BLE_CREATE_BIG_CPL_EVT:
        process_create_big_cmpl_pkt(packet_len, packet);
        break;
      case HCI_BLE_TERM_BIG_CPL_EVT:
        process_terminate_big_cmpl_pkt(packet_len, packet);
        break;
      case HCI_BLE_CIS_REQ_EVT:
        /* Not supported */
        break;
      case HCI_BLE_BIG_SYNC_EST_EVT:
        /* Not supported */
        break;
      case HCI_BLE_BIG_SYNC_LOST_EVT:
        /* Not supported */
        break;
      default:
        LOG_ERROR("Unhandled event code %d", +code);
    }
  }

  void handle_iso_data(BT_HDR* p_msg) {
    const uint8_t* stream = p_msg->data;
    cis_data_evt evt;
    uint16_t handle, seq_nb;

    if (p_msg->len <= ((p_msg->layer_specific & BT_ISO_HDR_CONTAINS_TS)
                           ? kIsoHeaderWithTsLen
                           : kIsoHeaderWithoutTsLen))
      return;

    LOG_ASSERT(cig_callbacks_ != nullptr) << "Invalid CIG callbacks";

    STREAM_TO_UINT16(handle, stream);
    evt.cis_conn_hdl = HCID_GET_HANDLE(handle);

    iso_base* iso = GetCisIfKnown(evt.cis_conn_hdl);
    if (iso == nullptr) {
      LOG(ERROR) << __func__ << ", received data for the non-registered CIS!";
      return;
    }

    STREAM_SKIP_UINT16(stream);
    if (p_msg->layer_specific & BT_ISO_HDR_CONTAINS_TS)
      STREAM_TO_UINT32(evt.ts, stream);

    STREAM_TO_UINT16(seq_nb, stream);

    uint32_t ts = bluetooth::common::time_get_os_boottime_us();
    uint32_t new_calc_seq_nb =
        (ts - iso->sync_info.first_sync_ts) / iso->sdu_itv;
    if (new_calc_seq_nb == iso->sync_info.seq_nb) ++new_calc_seq_nb;

    if (iso->sync_info.seq_nb == 0) {
      evt.evt_lost = 0;
    } else {
      evt.evt_lost = new_calc_seq_nb - iso->sync_info.seq_nb - 1;
      if (evt.evt_lost > 0) {
        LOG(WARNING) << evt.evt_lost << " packets possibly lost.";
      }

      if (new_calc_seq_nb != seq_nb) {
        LOG(WARNING) << "Sequence number mismatch. "
                        "Adjusting own time reference point.";
        iso->sync_info.first_sync_ts = ts - (seq_nb * iso->sdu_itv);
        new_calc_seq_nb = seq_nb;
      }
    }
    iso->sync_info.seq_nb = new_calc_seq_nb;

    evt.p_msg = p_msg;
    evt.cig_id = iso->cig_id;
    cig_callbacks_->OnCisEvent(kIsoEventCisDataAvailable, &evt);
  }

  iso_cis* GetCisIfKnown(uint16_t cis_conn_handle) {
    auto cis_it = conn_hdl_to_cis_map_.find(cis_conn_handle);
    return (cis_it != conn_hdl_to_cis_map_.end()) ? cis_it->second.get()
                                                  : nullptr;
  }

  iso_bis* GetBisIfKnown(uint16_t bis_conn_handle) {
    auto bis_it = conn_hdl_to_bis_map_.find(bis_conn_handle);
    return (bis_it != conn_hdl_to_bis_map_.end()) ? bis_it->second.get()
                                                  : nullptr;
  }

  iso_base* GetIsoIfKnown(uint16_t iso_handle) {
    struct iso_base* iso = GetCisIfKnown(iso_handle);
    return (iso != nullptr) ? iso : GetBisIfKnown(iso_handle);
  }

  bool IsCigKnown(uint8_t cig_id) const {
    auto const cis_it =
        std::find_if(conn_hdl_to_cis_map_.cbegin(), conn_hdl_to_cis_map_.cend(),
                     [&cig_id](auto& kv_pair) {
                       return (kv_pair.second->cig_id == cig_id);
                     });
    return (cis_it != conn_hdl_to_cis_map_.cend());
  }

  bool IsBigKnown(uint8_t big_id) const {
    auto bis_it =
        std::find_if(conn_hdl_to_bis_map_.cbegin(), conn_hdl_to_bis_map_.cend(),
                     [&big_id](auto& kv_pair) {
                       return (kv_pair.second->big_handle == big_id);
                     });
    return (bis_it != conn_hdl_to_bis_map_.cend());
  }

  std::map<uint16_t, std::unique_ptr<iso_cis>> conn_hdl_to_cis_map_;
  std::map<uint16_t, std::unique_ptr<iso_bis>> conn_hdl_to_bis_map_;

  uint16_t iso_credits_;
  uint16_t iso_buffer_size_;
  uint32_t last_big_create_req_sdu_itv_;

  CigCallbacks* cig_callbacks_ = nullptr;
  BigCallbacks* big_callbacks_ = nullptr;
};

}  // namespace iso_manager
}  // namespace hci
}  // namespace bluetooth
