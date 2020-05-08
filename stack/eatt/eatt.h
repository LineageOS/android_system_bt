/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com. Represented by EHIMA -
 * www.ehima.com
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

#include <queue>

#include "stack/gatt/gatt_int.h"

#define EATT_MIN_MTU_MPS (64)
#define EATT_DEFAULT_MTU (256)

namespace bluetooth {
namespace eatt {

/* Enums */
enum class EattChannelState : uint8_t {
  EATT_CHANNEL_PENDING = 0x00,
  EATT_CHANNEL_OPENED,
  EATT_CHANNEL_RECONFIGURING,
};

class EattChannel {
 public:
  /* Pointer to EattDevice */
  RawAddress bda_;
  uint16_t cid_;
  uint16_t tx_mtu_;
  uint16_t rx_mtu_;
  EattChannelState state_;

  /* Used to keep server commands */
  tGATT_SR_CMD server_outstanding_cmd_;
  /* Used to veryfy indication confirmation*/
  uint16_t indicate_handle_;
  /* local app confirm to indication timer */
  alarm_t* ind_ack_timer_;
  /* indication confirmation timer */
  alarm_t* ind_confirmation_timer_;
  /* GATT client command queue */
  std::queue<tGATT_CMD_Q> cl_cmd_q_;

  EattChannel(RawAddress& bda, uint16_t cid, uint16_t tx_mtu, uint16_t rx_mtu)
      : bda_(bda),
        cid_(cid),
        tx_mtu_(tx_mtu),
        rx_mtu_(rx_mtu),
        state_(EattChannelState::EATT_CHANNEL_PENDING),
        indicate_handle_(0),
        ind_ack_timer_(NULL),
        ind_confirmation_timer_(NULL) {}

  ~EattChannel() {
    if (ind_ack_timer_ != NULL) {
      alarm_free(ind_ack_timer_);
    }

    if (ind_confirmation_timer_ != NULL) {
      alarm_free(ind_confirmation_timer_);
    }
  }

  void EattChannelSetState(EattChannelState state) {
    if (state_ == EattChannelState::EATT_CHANNEL_PENDING) {
      if (state == EattChannelState::EATT_CHANNEL_OPENED) {
        cl_cmd_q_ = std::queue<tGATT_CMD_Q>();
        memset(&server_outstanding_cmd_, 0, sizeof(tGATT_SR_CMD));
        char name[64];
        sprintf(name, "eatt_ind_ack_timer_%s_cid_0x%04x",
                bda_.ToString().c_str(), cid_);
        ind_ack_timer_ = alarm_new(name);

        sprintf(name, "eatt_ind_conf_timer_%s_cid_0x%04x",
                bda_.ToString().c_str(), cid_);
        ind_confirmation_timer_ = alarm_new(name);
      }
    }
    state_ = state;
  }
  void EattChannelSetTxMTU(uint16_t tx_mtu) { this->tx_mtu_ = tx_mtu; }
};

/* Interface class */
class EattExtension {
 public:
  EattExtension();
  virtual ~EattExtension();

  static EattExtension* GetInstance() {
    static EattExtension* instance = new EattExtension();
    return instance;
  }

  static void AddFromStorage(const RawAddress& bd_addr);

  /**
   * Checks if EATT is supported on peer device.
   *
   * @param bd_addr peer device address
   */
  virtual bool IsEattSupportedByPeer(const RawAddress& bd_addr);

  /**
   * Connect at maximum 5 EATT channels to peer device.
   *
   * @param bd_addr peer device address
   */
  virtual void Connect(const RawAddress& bd_addr);

  /**
   * Disconnect all EATT channels to peer device.
   *
   * @param bd_addr peer device address
   */
  virtual void Disconnect(const RawAddress& bd_addr);

  /**
   * Reconfigure EATT channel for give CID
   *
   * @param bd_addr peer device address
   * @param cid channel id
   * @param mtu new maximum transmit unit available of local device
   */
  virtual void Reconfigure(const RawAddress& bd_addr, uint16_t cid,
                           uint16_t mtu);

  /**
   * Reconfigure all EATT channels to peer device.
   *
   * @param bd_addr peer device address
   * @param mtu new maximum transmit unit available of local device
   */
  virtual void ReconfigureAll(const RawAddress& bd_addr, uint16_t mtu);

  /* Below methods required by GATT implementation */

  /**
   * Find EATT channel by cid.
   *
   * @param bd_addr peer device address
   * @param cid channel id
   *
   * @return Eatt Channel instance.
   */
  virtual EattChannel* FindEattChannelByCid(const RawAddress& bd_addr,
                                            uint16_t cid);

  /**
   * Find EATT channel by transaction id.
   *
   * @param bd_addr peer device address
   * @param trans_id transaction id
   *
   * @return pointer to EATT channel.
   */
  virtual EattChannel* FindEattChannelByTransId(const RawAddress& bd_addr,
                                                uint32_t trans_id);

  /**
   * Check if EATT channel on given handle is waiting for a indication
   * confirmation
   *
   * @param bd_addr peer device address
   * @param indication_handle handle of the pending indication
   *
   * @return true if confirmation is pending false otherwise
   */
  virtual bool IsIndicationPending(const RawAddress& bd_addr,
                                   uint16_t indication_handle);

  /**
   * Get EATT channel available for indication.
   *
   * @param bd_addr peer device address
   *
   * @return pointer to EATT channel.
   */
  virtual EattChannel* GetChannelAvailableForIndication(
      const RawAddress& bd_addr);

  /**
   * Free Resources.
   *
   * (Maybe not needed)
   * @param bd_addr peer device address
   *
   */
  virtual void FreeGattResources(const RawAddress& bd_addr);

  /**
   * Check if there is any EATT channels having some msg in its send queue
   *
   * @param bd_addr peer device address
   *
   * @return true when there is at least one EATT channel ready to send
   */
  virtual bool IsOutstandingMsgInSendQueue(const RawAddress& bd_addr);

  /**
   * Get EATT channel ready to send.
   *
   * @param bd_addr peer device address
   *
   * @return pointer to EATT channel.
   */
  virtual EattChannel* GetChannelWithQueuedData(const RawAddress& bd_addr);

  /**
   * Get EATT channel available to send GATT request.
   *
   * @param bd_addr peer device address
   *
   * @return pointer to EATT channel.
   */
  virtual EattChannel* GetChannelAvailableForClientRequest(
      const RawAddress& bd_addr);

  /**
   * Start GATT indication timer per CID.
   *
   * @param bd_addr peer device address
   * @param cid channel id
   */
  virtual void StartIndicationConfirmationTimer(const RawAddress& bd_addr,
                                                uint16_t cid);

  /**
   * Stop GATT indication timer per CID.
   *
   * @param bd_addr peer device address
   * @param cid channel id
   */
  virtual void StopIndicationConfirmationTimer(const RawAddress& bd_addr,
                                               uint16_t cid);

  /**
   *  Start application time for incoming indication on given CID
   *
   * @param bd_addr peer device address
   * @param cid channel id
   */
  virtual void StartAppIndicationTimer(const RawAddress& bd_addr, uint16_t cid);

  /**
   *  Stop application time for incoming indication on given CID
   *
   * @param bd_addr peer device address
   * @param cid channel id
   */
  virtual void StopAppIndicationTimer(const RawAddress& bd_addr, uint16_t cid);

  /**
   * Starts the EattExtension module
   */
  void Start();

  /**
   * Stops the EattExtension module
   */
  void Stop();

 private:
  struct impl;
  std::unique_ptr<impl> pimpl_;

  DISALLOW_COPY_AND_ASSIGN(EattExtension);
};

}  // namespace eatt
}  // namespace bluetooth