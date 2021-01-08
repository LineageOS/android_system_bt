/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/******************************************************************************
 *
 *  This file contains functions for BLE device control utilities, and LE
 *  security functions.
 *
 ******************************************************************************/

#define LOG_TAG "bt_btm_ble"

#include <cstdint>

#include "device/include/controller.h"
#include "main/shim/btm_api.h"
#include "main/shim/shim.h"
#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_int_types.h"
#include "stack/btm/security_device_record.h"
#include "stack/crypto_toolbox/crypto_toolbox.h"
#include "stack/include/acl_api.h"
#include "stack/include/bt_types.h"
#include "stack/include/btm_api.h"
#include "stack/include/btu.h"
#include "stack/include/gatt_api.h"
#include "stack/include/l2cap_security_interface.h"
#include "stack/include/l2cdefs.h"
#include "stack/include/smp_api.h"
#include "types/raw_address.h"

extern tBTM_CB btm_cb;

extern bool btm_ble_init_pseudo_addr(tBTM_SEC_DEV_REC* p_dev_rec,
                                     const RawAddress& new_pseudo_addr);
extern void gatt_notify_phy_updated(tGATT_STATUS status, uint16_t handle,
                                    uint8_t tx_phy, uint8_t rx_phy);

/******************************************************************************/
/* External Function to be called by other modules                            */
/******************************************************************************/
void BTM_SecAddBleDevice(const RawAddress& bd_addr, tBT_DEVICE_TYPE dev_type,
                         tBLE_ADDR_TYPE addr_type) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_SecAddBleDevice(bd_addr, dev_type, addr_type);
  }

  BTM_TRACE_DEBUG("%s: dev_type=0x%x", __func__, dev_type);

  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);
  if (!p_dev_rec) {
    p_dev_rec = btm_sec_allocate_dev_rec();

    p_dev_rec->bd_addr = bd_addr;
    p_dev_rec->hci_handle = BTM_GetHCIConnHandle(bd_addr, BT_TRANSPORT_BR_EDR);
    p_dev_rec->ble_hci_handle = BTM_GetHCIConnHandle(bd_addr, BT_TRANSPORT_LE);

    /* update conn params, use default value for background connection params */
    p_dev_rec->conn_params.min_conn_int = BTM_BLE_CONN_PARAM_UNDEF;
    p_dev_rec->conn_params.max_conn_int = BTM_BLE_CONN_PARAM_UNDEF;
    p_dev_rec->conn_params.supervision_tout = BTM_BLE_CONN_PARAM_UNDEF;
    p_dev_rec->conn_params.peripheral_latency = BTM_BLE_CONN_PARAM_UNDEF;

    BTM_TRACE_DEBUG("%s: Device added, handle=0x%x, p_dev_rec=%p, bd_addr=%s",
                    __func__, p_dev_rec->ble_hci_handle, p_dev_rec,
                    bd_addr.ToString().c_str());
  }

  memset(p_dev_rec->sec_bd_name, 0, sizeof(tBTM_BD_NAME));

  p_dev_rec->device_type |= dev_type;
  p_dev_rec->ble.ble_addr_type = addr_type;

  p_dev_rec->ble.pseudo_addr = bd_addr;
  /* sync up with the Inq Data base*/
  tBTM_INQ_INFO* p_info = BTM_InqDbRead(bd_addr);
  if (p_info) {
    p_info->results.ble_addr_type = p_dev_rec->ble.ble_addr_type;
    p_info->results.device_type = p_dev_rec->device_type;
    BTM_TRACE_DEBUG("InqDb  device_type =0x%x  addr_type=0x%x",
                    p_info->results.device_type, p_info->results.ble_addr_type);
  }
}

/*******************************************************************************
 *
 * Function         BTM_SecAddBleKey
 *
 * Description      Add/modify LE device information.  This function will be
 *                  normally called during host startup to restore all required
 *                  information stored in the NVRAM.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  p_le_key         - LE key values.
 *                  key_type         - LE SMP key type.
*
 * Returns          true if added OK, else false
 *
 ******************************************************************************/
void BTM_SecAddBleKey(const RawAddress& bd_addr, tBTM_LE_KEY_VALUE* p_le_key,
                      tBTM_LE_KEY_TYPE key_type) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_SecAddBleKey(bd_addr, p_le_key, key_type);
  }

  tBTM_SEC_DEV_REC* p_dev_rec;
  BTM_TRACE_DEBUG("BTM_SecAddBleKey");
  p_dev_rec = btm_find_dev(bd_addr);
  if (!p_dev_rec || !p_le_key ||
      (key_type != BTM_LE_KEY_PENC && key_type != BTM_LE_KEY_PID &&
       key_type != BTM_LE_KEY_PCSRK && key_type != BTM_LE_KEY_LENC &&
       key_type != BTM_LE_KEY_LCSRK && key_type != BTM_LE_KEY_LID)) {
    LOG(WARNING) << __func__
                 << " Wrong Type, or No Device record for bdaddr: " << bd_addr
                 << ", Type: " << key_type;
    return;
  }

  VLOG(1) << __func__ << " BDA: " << bd_addr << ", Type: " << key_type;

  btm_sec_save_le_key(bd_addr, key_type, p_le_key, false);

  if (key_type == BTM_LE_KEY_PID || key_type == BTM_LE_KEY_LID) {
    btm_ble_resolving_list_load_dev(p_dev_rec);
  }
}

/*******************************************************************************
 *
 * Function         BTM_BleLoadLocalKeys
 *
 * Description      Local local identity key, encryption root or sign counter.
 *
 * Parameters:      key_type: type of key, can be BTM_BLE_KEY_TYPE_ID,
 *                                                BTM_BLE_KEY_TYPE_ER
 *                                             or BTM_BLE_KEY_TYPE_COUNTER.
 *                  p_key: pointer to the key.
 *
 * Returns          non2.
 *
 ******************************************************************************/
void BTM_BleLoadLocalKeys(uint8_t key_type, tBTM_BLE_LOCAL_KEYS* p_key) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleLoadLocalKeys(key_type, p_key);
  }

  tBTM_DEVCB* p_devcb = &btm_cb.devcb;
  BTM_TRACE_DEBUG("%s", __func__);
  if (p_key != NULL) {
    switch (key_type) {
      case BTM_BLE_KEY_TYPE_ID:
        memcpy(&p_devcb->id_keys, &p_key->id_keys,
               sizeof(tBTM_BLE_LOCAL_ID_KEYS));
        break;

      case BTM_BLE_KEY_TYPE_ER:
        p_devcb->ble_encryption_key_value = p_key->er;
        break;

      default:
        BTM_TRACE_ERROR("unknow local key type: %d", key_type);
        break;
    }
  }
}

/** Returns local device encryption root (ER) */
const Octet16& BTM_GetDeviceEncRoot() {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_GetDeviceEncRoot();
  }
  return btm_cb.devcb.ble_encryption_key_value;
}

/** Returns local device identity root (IR). */
const Octet16& BTM_GetDeviceIDRoot() {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_GetDeviceIDRoot();
  }
  return btm_cb.devcb.id_keys.irk;
}

/** Return local device DHK. */
const Octet16& BTM_GetDeviceDHK() {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_GetDeviceDHK();
  }
  return btm_cb.devcb.id_keys.dhk;
}


/*******************************************************************************
 *
 * Function         BTM_SecurityGrant
 *
 * Description      This function is called to grant security process.
 *
 * Parameters       bd_addr - peer device bd address.
 *                  res     - result of the operation BTM_SUCCESS if success.
 *                            Otherwise, BTM_REPEATED_ATTEMPTS if too many
 *                            attempts.
 *
 * Returns          None
 *
 ******************************************************************************/
void BTM_SecurityGrant(const RawAddress& bd_addr, uint8_t res) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_SecurityGrant(bd_addr, res);
  }
  tSMP_STATUS res_smp =
      (res == BTM_SUCCESS) ? SMP_SUCCESS : SMP_REPEATED_ATTEMPTS;
  BTM_TRACE_DEBUG("BTM_SecurityGrant");
  SMP_SecurityGrant(bd_addr, res_smp);
}

/*******************************************************************************
 *
 * Function         BTM_BlePasskeyReply
 *
 * Description      This function is called after Security Manager submitted
 *                  passkey request to the application.
 *
 * Parameters:      bd_addr - Address of the device for which passkey was
 *                            requested
 *                  res     - result of the operation BTM_SUCCESS if success
 *                  key_len - length in bytes of the Passkey
 *                  p_passkey    - pointer to array with the passkey
 *
 ******************************************************************************/
void BTM_BlePasskeyReply(const RawAddress& bd_addr, uint8_t res,
                         uint32_t passkey) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    ASSERT_LOG(false, "This should not be invoked from code path");
  }
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);
  tSMP_STATUS res_smp =
      (res == BTM_SUCCESS) ? SMP_SUCCESS : SMP_PASSKEY_ENTRY_FAIL;

  if (p_dev_rec == NULL) {
    BTM_TRACE_ERROR("Passkey reply to Unknown device");
    return;
  }

  p_dev_rec->sec_flags |= BTM_SEC_LE_AUTHENTICATED;
  BTM_TRACE_DEBUG("BTM_BlePasskeyReply");
  SMP_PasskeyReply(bd_addr, res_smp, passkey);
}

/*******************************************************************************
 *
 * Function         BTM_BleConfirmReply
 *
 * Description      This function is called after Security Manager submitted
 *                  numeric comparison request to the application.
 *
 * Parameters:      bd_addr      - Address of the device with which numeric
 *                                 comparison was requested
 *                  res          - comparison result BTM_SUCCESS if success
 *
 ******************************************************************************/
void BTM_BleConfirmReply(const RawAddress& bd_addr, uint8_t res) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    ASSERT_LOG(false, "This should not be invoked from code path");
  }
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);
  tSMP_STATUS res_smp =
      (res == BTM_SUCCESS) ? SMP_SUCCESS : SMP_PASSKEY_ENTRY_FAIL;

  if (p_dev_rec == NULL) {
    BTM_TRACE_ERROR("Passkey reply to Unknown device");
    return;
  }

  p_dev_rec->sec_flags |= BTM_SEC_LE_AUTHENTICATED;
  BTM_TRACE_DEBUG("%s", __func__);
  SMP_ConfirmReply(bd_addr, res_smp);
}

/*******************************************************************************
 *
 * Function         BTM_BleOobDataReply
 *
 * Description      This function is called to provide the OOB data for
 *                  SMP in response to BTM_LE_OOB_REQ_EVT
 *
 * Parameters:      bd_addr     - Address of the peer device
 *                  res         - result of the operation SMP_SUCCESS if success
 *                  p_data      - oob data, depending on transport and
 *                                capabilities.
 *                                Might be "Simple Pairing Randomizer", or
 *                                "Security Manager TK Value".
 *
 ******************************************************************************/
void BTM_BleOobDataReply(const RawAddress& bd_addr, uint8_t res, uint8_t len,
                         uint8_t* p_data) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleOobDataReply(bd_addr, res, len, p_data);
  }
  tSMP_STATUS res_smp = (res == BTM_SUCCESS) ? SMP_SUCCESS : SMP_OOB_FAIL;
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);

  BTM_TRACE_DEBUG("%s:", __func__);

  if (p_dev_rec == NULL) {
    BTM_TRACE_ERROR("%s: Unknown device", __func__);
    return;
  }

  p_dev_rec->sec_flags |= BTM_SEC_LE_AUTHENTICATED;
  SMP_OobDataReply(bd_addr, res_smp, len, p_data);
}

/*******************************************************************************
 *
 * Function         BTM_BleSecureConnectionOobDataReply
 *
 * Description      This function is called to provide the OOB data for
 *                  SMP in response to BTM_LE_OOB_REQ_EVT when secure connection
 *                  data is available
 *
 * Parameters:      bd_addr     - Address of the peer device
 *                  p_c         - pointer to Confirmation.
 *                  p_r         - pointer to Randomizer
 *
 ******************************************************************************/
void BTM_BleSecureConnectionOobDataReply(const RawAddress& bd_addr,
                                         uint8_t* p_c, uint8_t* p_r) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleSecureConnectionOobDataReply(bd_addr, p_c,
                                                                p_r);
  }
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);

  BTM_TRACE_DEBUG("%s:", __func__);

  if (p_dev_rec == NULL) {
    BTM_TRACE_ERROR("%s: Unknown device", __func__);
    return;
  }

  p_dev_rec->sec_flags |= BTM_SEC_LE_AUTHENTICATED;

  tSMP_SC_OOB_DATA oob;
  memset(&oob, 0, sizeof(tSMP_SC_OOB_DATA));

  oob.peer_oob_data.present = true;
  memcpy(&oob.peer_oob_data.randomizer, p_r, OCTET16_LEN);
  memcpy(&oob.peer_oob_data.commitment, p_c, OCTET16_LEN);
  oob.peer_oob_data.addr_rcvd_from.type = p_dev_rec->ble.ble_addr_type;
  oob.peer_oob_data.addr_rcvd_from.bda = bd_addr;

  SMP_SecureConnectionOobDataReply((uint8_t*)&oob);
}

/********************************************************
 *
 * Function         BTM_BleSetPrefConnParams
 *
 * Description      Set a peripheral's preferred connection parameters
 *
 * Parameters:      bd_addr          - BD address of the peripheral
 *                  scan_interval: scan interval
 *                  scan_window: scan window
 *                  min_conn_int     - minimum preferred connection interval
 *                  max_conn_int     - maximum preferred connection interval
 *                  peripheral_latency    - preferred peripheral latency
 *                  supervision_tout - preferred supervision timeout
 *
 * Returns          void
 *
 ******************************************************************************/
void BTM_BleSetPrefConnParams(const RawAddress& bd_addr, uint16_t min_conn_int,
                              uint16_t max_conn_int,
                              uint16_t peripheral_latency,
                              uint16_t supervision_tout) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleSetPrefConnParams(
        bd_addr, min_conn_int, max_conn_int, peripheral_latency,
        supervision_tout);
  }
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);

  BTM_TRACE_API(
      "BTM_BleSetPrefConnParams min: %u  max: %u  latency: %u  \
                    tout: %u",
      min_conn_int, max_conn_int, peripheral_latency, supervision_tout);

  if (BTM_BLE_ISVALID_PARAM(min_conn_int, BTM_BLE_CONN_INT_MIN,
                            BTM_BLE_CONN_INT_MAX) &&
      BTM_BLE_ISVALID_PARAM(max_conn_int, BTM_BLE_CONN_INT_MIN,
                            BTM_BLE_CONN_INT_MAX) &&
      BTM_BLE_ISVALID_PARAM(supervision_tout, BTM_BLE_CONN_SUP_TOUT_MIN,
                            BTM_BLE_CONN_SUP_TOUT_MAX) &&
      (peripheral_latency <= BTM_BLE_CONN_LATENCY_MAX ||
       peripheral_latency == BTM_BLE_CONN_PARAM_UNDEF)) {
    if (p_dev_rec) {
      /* expect conn int and stout and peripheral latency to be updated all
       * together
       */
      if (min_conn_int != BTM_BLE_CONN_PARAM_UNDEF ||
          max_conn_int != BTM_BLE_CONN_PARAM_UNDEF) {
        if (min_conn_int != BTM_BLE_CONN_PARAM_UNDEF)
          p_dev_rec->conn_params.min_conn_int = min_conn_int;
        else
          p_dev_rec->conn_params.min_conn_int = max_conn_int;

        if (max_conn_int != BTM_BLE_CONN_PARAM_UNDEF)
          p_dev_rec->conn_params.max_conn_int = max_conn_int;
        else
          p_dev_rec->conn_params.max_conn_int = min_conn_int;

        if (peripheral_latency != BTM_BLE_CONN_PARAM_UNDEF)
          p_dev_rec->conn_params.peripheral_latency = peripheral_latency;
        else
          p_dev_rec->conn_params.peripheral_latency =
              BTM_BLE_CONN_PERIPHERAL_LATENCY_DEF;

        if (supervision_tout != BTM_BLE_CONN_PARAM_UNDEF)
          p_dev_rec->conn_params.supervision_tout = supervision_tout;
        else
          p_dev_rec->conn_params.supervision_tout = BTM_BLE_CONN_TIMEOUT_DEF;
      }

    } else {
      BTM_TRACE_ERROR("Unknown Device, setting rejected");
    }
  } else {
    BTM_TRACE_ERROR("Illegal Connection Parameters");
  }
}

/*******************************************************************************
 *
 * Function         BTM_ReadDevInfo
 *
 * Description      This function is called to read the device/address type
 *                  of BD address.
 *
 * Parameter        remote_bda: remote device address
 *                  p_dev_type: output parameter to read the device type.
 *                  p_addr_type: output parameter to read the address type.
 *
 ******************************************************************************/
void BTM_ReadDevInfo(const RawAddress& remote_bda, tBT_DEVICE_TYPE* p_dev_type,
                     tBLE_ADDR_TYPE* p_addr_type) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(remote_bda);
  tBTM_INQ_INFO* p_inq_info = BTM_InqDbRead(remote_bda);

  *p_addr_type = BLE_ADDR_PUBLIC;

  if (!p_dev_rec) {
    *p_dev_type = BT_DEVICE_TYPE_BREDR;
    /* Check with the BT manager if details about remote device are known */
    if (p_inq_info != NULL) {
      *p_dev_type = p_inq_info->results.device_type;
      *p_addr_type = p_inq_info->results.ble_addr_type;
    } else {
      /* unknown device, assume BR/EDR */
      BTM_TRACE_DEBUG("btm_find_dev_type - unknown device, BR/EDR assumed");
    }
  } else /* there is a security device record exisitng */
  {
    /* new inquiry result, overwrite device type in security device record */
    if (p_inq_info) {
      p_dev_rec->device_type = p_inq_info->results.device_type;
      p_dev_rec->ble.ble_addr_type = p_inq_info->results.ble_addr_type;
    }
    if (p_dev_rec->bd_addr == remote_bda &&
        p_dev_rec->ble.pseudo_addr == remote_bda) {
      *p_dev_type = p_dev_rec->device_type;
      *p_addr_type = p_dev_rec->ble.ble_addr_type;
    } else if (p_dev_rec->ble.pseudo_addr == remote_bda) {
      *p_dev_type = BT_DEVICE_TYPE_BLE;
      *p_addr_type = p_dev_rec->ble.ble_addr_type;
    } else /* matching static adddress only */
    {
      *p_dev_type = BT_DEVICE_TYPE_BREDR;
      *p_addr_type = BLE_ADDR_PUBLIC;
    }
  }

  BTM_TRACE_DEBUG("btm_find_dev_type - device_type = %d addr_type = %d",
                  *p_dev_type, *p_addr_type);
}

/*******************************************************************************
 *
 * Function         BTM_ReadConnectedTransportAddress
 *
 * Description      This function is called to read the paired device/address
 *                  type of other device paired corresponding to the BD_address
 *
 * Parameter        remote_bda: remote device address, carry out the transport
 *                              address
 *                  transport: active transport
 *
 * Return           true if an active link is identified; false otherwise
 *
 ******************************************************************************/
bool BTM_ReadConnectedTransportAddress(RawAddress* remote_bda,
                                       tBT_TRANSPORT transport) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_ReadConnectedTransportAddress(remote_bda,
                                                              transport);
  }
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(*remote_bda);

  /* if no device can be located, return */
  if (p_dev_rec == NULL) return false;

  if (transport == BT_TRANSPORT_BR_EDR) {
    if (BTM_IsAclConnectionUp(p_dev_rec->bd_addr, transport)) {
      *remote_bda = p_dev_rec->bd_addr;
      return true;
    } else if (p_dev_rec->device_type & BT_DEVICE_TYPE_BREDR) {
      *remote_bda = p_dev_rec->bd_addr;
    } else
      *remote_bda = RawAddress::kEmpty;
    return false;
  }

  if (transport == BT_TRANSPORT_LE) {
    *remote_bda = p_dev_rec->ble.pseudo_addr;
    if (BTM_IsAclConnectionUp(p_dev_rec->ble.pseudo_addr, transport))
      return true;
    else
      return false;
  }

  return false;
}

/*******************************************************************************
 *
 * Function         BTM_BleReceiverTest
 *
 * Description      This function is called to start the LE Receiver test
 *
 * Parameter       rx_freq - Frequency Range
 *               p_cmd_cmpl_cback - Command Complete callback
 *
 ******************************************************************************/
void BTM_BleReceiverTest(uint8_t rx_freq, tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleReceiverTest(rx_freq, p_cmd_cmpl_cback);
  }
  btm_cb.devcb.p_le_test_cmd_cmpl_cb = p_cmd_cmpl_cback;

  btsnd_hcic_ble_receiver_test(rx_freq);
}

/*******************************************************************************
 *
 * Function         BTM_BleTransmitterTest
 *
 * Description      This function is called to start the LE Transmitter test
 *
 * Parameter       tx_freq - Frequency Range
 *                       test_data_len - Length in bytes of payload data in each
 *                                       packet
 *                       packet_payload - Pattern to use in the payload
 *                       p_cmd_cmpl_cback - Command Complete callback
 *
 ******************************************************************************/
void BTM_BleTransmitterTest(uint8_t tx_freq, uint8_t test_data_len,
                            uint8_t packet_payload,
                            tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleTransmitterTest(
        tx_freq, test_data_len, packet_payload, p_cmd_cmpl_cback);
  }
  btm_cb.devcb.p_le_test_cmd_cmpl_cb = p_cmd_cmpl_cback;
  btsnd_hcic_ble_transmitter_test(tx_freq, test_data_len, packet_payload);
}

/*******************************************************************************
 *
 * Function         BTM_BleTestEnd
 *
 * Description      This function is called to stop the in-progress TX or RX
 *                  test
 *
 * Parameter       p_cmd_cmpl_cback - Command complete callback
 *
 ******************************************************************************/
void BTM_BleTestEnd(tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleTestEnd(p_cmd_cmpl_cback);
  }
  btm_cb.devcb.p_le_test_cmd_cmpl_cb = p_cmd_cmpl_cback;

  btsnd_hcic_ble_test_end();
}

/*******************************************************************************
 * Internal Functions
 ******************************************************************************/
void btm_ble_test_command_complete(uint8_t* p) {
  tBTM_CMPL_CB* p_cb = btm_cb.devcb.p_le_test_cmd_cmpl_cb;

  btm_cb.devcb.p_le_test_cmd_cmpl_cb = NULL;

  if (p_cb) {
    (*p_cb)(p);
  }
}

/*******************************************************************************
 *
 * Function         BTM_UseLeLink
 *
 * Description      This function is to select the underlying physical link to
 *                  use.
 *
 * Returns          true to use LE, false use BR/EDR.
 *
 ******************************************************************************/
bool BTM_UseLeLink(const RawAddress& bd_addr) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_UseLeLink(bd_addr);
  }

  if (BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_BR_EDR)) {
    return false;
  } else if (BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE)) {
    return true;
  }

  tBT_DEVICE_TYPE dev_type;
  tBLE_ADDR_TYPE addr_type;
  BTM_ReadDevInfo(bd_addr, &dev_type, &addr_type);
  return (dev_type == BT_DEVICE_TYPE_BLE);
}

tBTM_STATUS BTM_SetBleDataLength(const RawAddress& bd_addr,
                                 uint16_t tx_pdu_length) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_SetBleDataLength(bd_addr, tx_pdu_length);
  }
  uint16_t tx_time = BTM_BLE_DATA_TX_TIME_MAX_LEGACY;

  if (!BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE)) {
    LOG_INFO(
        "Unable to set data length because no le acl link connected to device");
    return BTM_WRONG_MODE;
  }

  if (!controller_get_interface()->supports_ble_packet_extension()) {
    LOG_INFO("Local controller unable to support le packet extension");
    return BTM_ILLEGAL_VALUE;
  }

  uint16_t hci_handle = acl_get_hci_handle_for_hcif(bd_addr, BT_TRANSPORT_LE);

  if (!acl_peer_supports_ble_packet_extension(hci_handle)) {
    LOG_INFO("Remote device unable to support le packet extension");
    return BTM_ILLEGAL_VALUE;
  }

  if (tx_pdu_length > BTM_BLE_DATA_SIZE_MAX)
    tx_pdu_length = BTM_BLE_DATA_SIZE_MAX;
  else if (tx_pdu_length < BTM_BLE_DATA_SIZE_MIN)
    tx_pdu_length = BTM_BLE_DATA_SIZE_MIN;

  if (controller_get_interface()->get_bt_version()->hci_version >= HCI_PROTO_VERSION_5_0)
    tx_time = BTM_BLE_DATA_TX_TIME_MAX;

  btsnd_hcic_ble_set_data_length(hci_handle, tx_pdu_length, tx_time);

  return BTM_SUCCESS;
}

void read_phy_cb(
    base::Callback<void(uint8_t tx_phy, uint8_t rx_phy, uint8_t status)> cb,
    uint8_t* data, uint16_t len) {
  uint8_t status, tx_phy, rx_phy;
  uint16_t handle;

  LOG_ASSERT(len == 5) << "Received bad response length: " << len;
  uint8_t* pp = data;
  STREAM_TO_UINT8(status, pp);
  STREAM_TO_UINT16(handle, pp);
  handle = handle & 0x0FFF;
  STREAM_TO_UINT8(tx_phy, pp);
  STREAM_TO_UINT8(rx_phy, pp);

  DVLOG(1) << __func__ << " Received read_phy_cb";
  cb.Run(tx_phy, rx_phy, status);
}

/*******************************************************************************
 *
 * Function         BTM_BleReadPhy
 *
 * Description      To read the current PHYs for specified LE connection
 *
 *
 * Returns          BTM_SUCCESS if command successfully sent to controller,
 *                  BTM_MODE_UNSUPPORTED if local controller doesn't support LE
 *                  2M or LE Coded PHY,
 *                  BTM_WRONG_MODE if Device in wrong mode for request.
 *
 ******************************************************************************/
void BTM_BleReadPhy(
    const RawAddress& bd_addr,
    base::Callback<void(uint8_t tx_phy, uint8_t rx_phy, uint8_t status)> cb) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleReadPhy(bd_addr, cb);
  }
  BTM_TRACE_DEBUG("%s", __func__);

  if (!BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE)) {
    BTM_TRACE_ERROR("%s: Wrong mode: no LE link exist or LE not supported",
                    __func__);
    cb.Run(0, 0, HCI_ERR_NO_CONNECTION);
    return;
  }

  // checking if local controller supports it!
  if (!controller_get_interface()->supports_ble_2m_phy() &&
      !controller_get_interface()->supports_ble_coded_phy()) {
    BTM_TRACE_ERROR("%s failed, request not supported in local controller!",
                    __func__);
    cb.Run(0, 0, GATT_REQ_NOT_SUPPORTED);
    return;
  }

  uint16_t handle = acl_get_hci_handle_for_hcif(bd_addr, BT_TRANSPORT_LE);

  const uint8_t len = HCIC_PARAM_SIZE_BLE_READ_PHY;
  uint8_t data[len];
  uint8_t* pp = data;
  UINT16_TO_STREAM(pp, handle);
  btu_hcif_send_cmd_with_cb(FROM_HERE, HCI_BLE_READ_PHY, data, len,
                            base::Bind(&read_phy_cb, std::move(cb)));
  return;
}

void doNothing(uint8_t* data, uint16_t len) {}

void BTM_BleSetPhy(const RawAddress& bd_addr, uint8_t tx_phys, uint8_t rx_phys,
                   uint16_t phy_options) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleSetPhy(bd_addr, tx_phys, rx_phys,
                                          phy_options);
  }
  if (!BTM_IsAclConnectionUp(bd_addr, BT_TRANSPORT_LE)) {
    LOG_INFO(
        "Unable to set phy preferences because no le acl is connected to "
        "device");
    return;
  }

  uint8_t all_phys = 0;
  if (tx_phys == 0) all_phys &= 0x01;
  if (rx_phys == 0) all_phys &= 0x02;

  uint16_t handle = acl_get_hci_handle_for_hcif(bd_addr, BT_TRANSPORT_LE);

  // checking if local controller supports it!
  if (!controller_get_interface()->supports_ble_2m_phy() &&
      !controller_get_interface()->supports_ble_coded_phy()) {
    LOG_INFO("Local controller unable to support setting of le phy parameters");
    gatt_notify_phy_updated(GATT_REQ_NOT_SUPPORTED, handle, tx_phys, rx_phys);
    return;
  }

  if (!acl_peer_supports_ble_2m_phy(handle) &&
      !acl_peer_supports_ble_coded_phy(handle)) {
    LOG_INFO("Remote device unable to support setting of le phy parameter");
    gatt_notify_phy_updated(GATT_REQ_NOT_SUPPORTED, handle, tx_phys, rx_phys);
    return;
  }

  const uint8_t len = HCIC_PARAM_SIZE_BLE_SET_PHY;
  uint8_t data[len];
  uint8_t* pp = data;
  UINT16_TO_STREAM(pp, handle);
  UINT8_TO_STREAM(pp, all_phys);
  UINT8_TO_STREAM(pp, tx_phys);
  UINT8_TO_STREAM(pp, rx_phys);
  UINT16_TO_STREAM(pp, phy_options);
  btu_hcif_send_cmd_with_cb(FROM_HERE, HCI_BLE_SET_PHY, data, len,
                            base::Bind(doNothing));
}

/*******************************************************************************
 *
 * Function         btm_ble_determine_security_act
 *
 * Description      This function checks the security of current LE link
 *                  and returns the appropriate action that needs to be
 *                  taken to achieve the required security.
 *
 * Parameter        is_originator - True if outgoing connection
 *                  bdaddr: remote device address
 *                  security_required: Security required for the service.
 *
 * Returns          The appropriate security action required.
 *
 ******************************************************************************/
tBTM_SEC_ACTION btm_ble_determine_security_act(bool is_originator,
                                               const RawAddress& bdaddr,
                                               uint16_t security_required) {
  tBTM_LE_AUTH_REQ auth_req = 0x00;

  if (is_originator) {
    if ((security_required & BTM_SEC_OUT_FLAGS) == 0 &&
        (security_required & BTM_SEC_OUT_MITM) == 0) {
      BTM_TRACE_DEBUG("%s No security required for outgoing connection",
                      __func__);
      return BTM_SEC_OK;
    }

    if (security_required & BTM_SEC_OUT_MITM) auth_req |= BTM_LE_AUTH_REQ_MITM;
  } else {
    if ((security_required & BTM_SEC_IN_FLAGS) == 0 &&
        (security_required & BTM_SEC_IN_MITM) == 0) {
      BTM_TRACE_DEBUG("%s No security required for incoming connection",
                      __func__);
      return BTM_SEC_OK;
    }

    if (security_required & BTM_SEC_IN_MITM) auth_req |= BTM_LE_AUTH_REQ_MITM;
  }

  tBTM_BLE_SEC_REQ_ACT ble_sec_act;
  btm_ble_link_sec_check(bdaddr, auth_req, &ble_sec_act);

  BTM_TRACE_DEBUG("%s ble_sec_act %d", __func__, ble_sec_act);

  if (ble_sec_act == BTM_BLE_SEC_REQ_ACT_DISCARD) return BTM_SEC_ENC_PENDING;

  if (ble_sec_act == BTM_BLE_SEC_REQ_ACT_NONE) return BTM_SEC_OK;

  bool is_link_encrypted = BTM_IsEncrypted(bdaddr, BT_TRANSPORT_LE);
  bool is_key_mitm = BTM_IsLinkKeyAuthed(bdaddr, BT_TRANSPORT_LE);

  if (auth_req & BTM_LE_AUTH_REQ_MITM) {
    if (!is_key_mitm) {
      return BTM_SEC_ENCRYPT_MITM;
    } else {
      if (is_link_encrypted)
        return BTM_SEC_OK;
      else
        return BTM_SEC_ENCRYPT;
    }
  } else {
    if (is_link_encrypted)
      return BTM_SEC_OK;
    else
      return BTM_SEC_ENCRYPT_NO_MITM;
  }

  return BTM_SEC_OK;
}

/*******************************************************************************
 *
 * Function         btm_ble_start_sec_check
 *
 * Description      This function is to check and set the security required for
 *                  LE link for LE COC.
 *
 * Parameter        bdaddr: remote device address.
 *                  psm : PSM of the LE COC sevice.
 *                  is_originator: true if outgoing connection.
 *                  p_callback : Pointer to the callback function.
 *                  p_ref_data : Pointer to be returned along with the callback.
 *
 * Returns          Returns  - L2CAP LE Connection Response Result Code.
 *
 ******************************************************************************/
tL2CAP_LE_RESULT_CODE btm_ble_start_sec_check(const RawAddress& bd_addr,
                                              uint16_t psm, bool is_originator,
                                              tBTM_SEC_CALLBACK* p_callback,
                                              void* p_ref_data) {
  /* Find the service record for the PSM */
  tBTM_SEC_SERV_REC* p_serv_rec = btm_sec_find_first_serv(is_originator, psm);

  /* If there is no application registered with this PSM do not allow connection
   */
  if (!p_serv_rec) {
    LOG_WARN("PSM: %d no application registered", psm);
    (*p_callback)(&bd_addr, BT_TRANSPORT_LE, p_ref_data, BTM_MODE_UNSUPPORTED);
    return L2CAP_LE_RESULT_NO_PSM;
  }

  bool is_encrypted = BTM_IsEncrypted(bd_addr, BT_TRANSPORT_LE);
  bool is_link_key_authed = BTM_IsLinkKeyAuthed(bd_addr, BT_TRANSPORT_LE);
  bool is_authenticated = BTM_IsAuthenticated(bd_addr, BT_TRANSPORT_LE);

  if (!is_originator) {
    if ((p_serv_rec->security_flags & BTM_SEC_IN_ENCRYPT) && !is_encrypted) {
      LOG_ERROR(
          "L2CAP_LE_RESULT_INSUFFICIENT_ENCRYP. service "
          "security_flags=0x%x, ",
          p_serv_rec->security_flags);
      return L2CAP_LE_RESULT_INSUFFICIENT_ENCRYP;
    } else if ((p_serv_rec->security_flags & BTM_SEC_IN_AUTHENTICATE) &&
               !(is_link_key_authed || is_authenticated)) {
      LOG_ERROR(
          "L2CAP_LE_RESULT_INSUFFICIENT_AUTHENTICATION. service "
          "security_flags=0x%x, ",
          p_serv_rec->security_flags);
      return L2CAP_LE_RESULT_INSUFFICIENT_AUTHENTICATION;
    }
    /* TODO: When security is required, then must check that the key size of our
       service is equal or smaller than the incoming connection key size. */
  }

  tBTM_SEC_ACTION sec_act = btm_ble_determine_security_act(
      is_originator, bd_addr, p_serv_rec->security_flags);

  tBTM_BLE_SEC_ACT ble_sec_act = BTM_BLE_SEC_NONE;
  tL2CAP_LE_RESULT_CODE result = L2CAP_LE_RESULT_CONN_OK;

  switch (sec_act) {
    case BTM_SEC_OK:
      LOG_DEBUG("Security met");
      p_callback(&bd_addr, BT_TRANSPORT_LE, p_ref_data, BTM_SUCCESS);
      result = L2CAP_LE_RESULT_CONN_OK;
      break;

    case BTM_SEC_ENCRYPT:
      LOG_DEBUG("Encryption needs to be done");
      ble_sec_act = BTM_BLE_SEC_ENCRYPT;
      break;

    case BTM_SEC_ENCRYPT_MITM:
      LOG_DEBUG("Pairing with MITM needs to be done");
      ble_sec_act = BTM_BLE_SEC_ENCRYPT_MITM;
      break;

    case BTM_SEC_ENCRYPT_NO_MITM:
      LOG_DEBUG("Pairing with No MITM needs to be done");
      ble_sec_act = BTM_BLE_SEC_ENCRYPT_NO_MITM;
      break;

    case BTM_SEC_ENC_PENDING:
      LOG_DEBUG("Ecryption pending");
      break;
  }

  if (ble_sec_act == BTM_BLE_SEC_NONE) {
    return result;
  }

  l2cble_update_sec_act(bd_addr, sec_act);
  BTM_SetEncryption(bd_addr, BT_TRANSPORT_LE, p_callback, p_ref_data,
                    ble_sec_act);

  return L2CAP_LE_RESULT_CONN_OK;
}

/*******************************************************************************
 *
 * Function         btm_ble_rand_enc_complete
 *
 * Description      This function is the callback functions for HCI_Rand command
 *                  and HCI_Encrypt command is completed.
 *                  This message is received from the HCI.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_rand_enc_complete(uint8_t* p, uint16_t op_code,
                               tBTM_RAND_ENC_CB* p_enc_cplt_cback) {
  tBTM_RAND_ENC params;
  uint8_t* p_dest = params.param_buf;

  BTM_TRACE_DEBUG("btm_ble_rand_enc_complete");

  memset(&params, 0, sizeof(tBTM_RAND_ENC));

  /* If there was a callback address for vcs complete, call it */
  if (p_enc_cplt_cback && p) {
    /* Pass paramters to the callback function */
    STREAM_TO_UINT8(params.status, p); /* command status */

    if (params.status == HCI_SUCCESS) {
      params.opcode = op_code;

      if (op_code == HCI_BLE_RAND)
        params.param_len = BT_OCTET8_LEN;
      else
        params.param_len = OCTET16_LEN;

      /* Fetch return info from HCI event message */
      memcpy(p_dest, p, params.param_len);
    }
    if (p_enc_cplt_cback) /* Call the Encryption complete callback function */
      (*p_enc_cplt_cback)(&params);
  }
}

/*******************************************************************************
 *
 * Function         btm_ble_get_enc_key_type
 *
 * Description      This function is to increment local sign counter
 * Returns         None
 *
 ******************************************************************************/
void btm_ble_increment_sign_ctr(const RawAddress& bd_addr, bool is_local) {
  tBTM_SEC_DEV_REC* p_dev_rec;

  BTM_TRACE_DEBUG("btm_ble_increment_sign_ctr is_local=%d", is_local);

  p_dev_rec = btm_find_dev(bd_addr);
  if (p_dev_rec != NULL) {
    if (is_local)
      p_dev_rec->ble.keys.local_counter++;
    else
      p_dev_rec->ble.keys.counter++;
    BTM_TRACE_DEBUG("is_local=%d local sign counter=%d peer sign counter=%d",
                    is_local, p_dev_rec->ble.keys.local_counter,
                    p_dev_rec->ble.keys.counter);
  }
}

/*******************************************************************************
 *
 * Function         btm_ble_get_enc_key_type
 *
 * Description      This function is to get the BLE key type that has been
 *                  exchanged betweem the local device and the peer device.
 *
 * Returns          p_key_type: output parameter to carry the key type value.
 *
 ******************************************************************************/
bool btm_ble_get_enc_key_type(const RawAddress& bd_addr, uint8_t* p_key_types) {
  tBTM_SEC_DEV_REC* p_dev_rec;

  BTM_TRACE_DEBUG("btm_ble_get_enc_key_type");

  p_dev_rec = btm_find_dev(bd_addr);
  if (p_dev_rec != NULL) {
    *p_key_types = p_dev_rec->ble.key_type;
    return true;
  }
  return false;
}

/*******************************************************************************
 *
 * Function         btm_get_local_div
 *
 * Description      This function is called to read the local DIV
 *
 * Returns          TURE - if a valid DIV is availavle
 ******************************************************************************/
bool btm_get_local_div(const RawAddress& bd_addr, uint16_t* p_div) {
  tBTM_SEC_DEV_REC* p_dev_rec;
  bool status = false;
  VLOG(1) << __func__ << " bd_addr: " << bd_addr;

  *p_div = 0;
  p_dev_rec = btm_find_dev(bd_addr);

  if (p_dev_rec && p_dev_rec->ble.keys.div) {
    status = true;
    *p_div = p_dev_rec->ble.keys.div;
  }
  BTM_TRACE_DEBUG("btm_get_local_div status=%d (1-OK) DIV=0x%x", status,
                  *p_div);
  return status;
}

/*******************************************************************************
 *
 * Function         btm_sec_save_le_key
 *
 * Description      This function is called by the SMP to update
 *                  an  BLE key.  SMP is internal, whereas all the keys shall
 *                  be sent to the application.  The function is also called
 *                  when application passes ble key stored in NVRAM to the
 *                  btm_sec.
 *                  pass_to_application parameter is false in this case.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_sec_save_le_key(const RawAddress& bd_addr, tBTM_LE_KEY_TYPE key_type,
                         tBTM_LE_KEY_VALUE* p_keys, bool pass_to_application) {
  tBTM_SEC_DEV_REC* p_rec;
  tBTM_LE_EVT_DATA cb_data;

  BTM_TRACE_DEBUG("btm_sec_save_le_key key_type=0x%x pass_to_application=%d",
                  key_type, pass_to_application);
  /* Store the updated key in the device database */

  VLOG(1) << "bd_addr:" << bd_addr;

  if ((p_rec = btm_find_dev(bd_addr)) != NULL &&
      (p_keys || key_type == BTM_LE_KEY_LID)) {
    btm_ble_init_pseudo_addr(p_rec, bd_addr);

    switch (key_type) {
      case BTM_LE_KEY_PENC:
        p_rec->ble.keys.pltk = p_keys->penc_key.ltk;
        memcpy(p_rec->ble.keys.rand, p_keys->penc_key.rand, BT_OCTET8_LEN);
        p_rec->ble.keys.sec_level = p_keys->penc_key.sec_level;
        p_rec->ble.keys.ediv = p_keys->penc_key.ediv;
        p_rec->ble.keys.key_size = p_keys->penc_key.key_size;
        p_rec->ble.key_type |= BTM_LE_KEY_PENC;
        p_rec->sec_flags |= BTM_SEC_LE_LINK_KEY_KNOWN;
        if (p_keys->penc_key.sec_level == SMP_SEC_AUTHENTICATED)
          p_rec->sec_flags |= BTM_SEC_LE_LINK_KEY_AUTHED;
        else
          p_rec->sec_flags &= ~BTM_SEC_LE_LINK_KEY_AUTHED;
        BTM_TRACE_DEBUG(
            "BTM_LE_KEY_PENC key_type=0x%x sec_flags=0x%x sec_leve=0x%x",
            p_rec->ble.key_type, p_rec->sec_flags, p_rec->ble.keys.sec_level);
        break;

      case BTM_LE_KEY_PID:
        p_rec->ble.keys.irk = p_keys->pid_key.irk;
        p_rec->ble.identity_address_with_type.bda =
            p_keys->pid_key.identity_addr;
        p_rec->ble.identity_address_with_type.type =
            p_keys->pid_key.identity_addr_type;
        p_rec->ble.key_type |= BTM_LE_KEY_PID;
        BTM_TRACE_DEBUG(
            "%s: BTM_LE_KEY_PID key_type=0x%x save peer IRK, change bd_addr=%s "
            "to id_addr=%s id_addr_type=0x%x",
            __func__, p_rec->ble.key_type, p_rec->bd_addr.ToString().c_str(),
            p_keys->pid_key.identity_addr.ToString().c_str(),
            p_keys->pid_key.identity_addr_type);
        /* update device record address as identity address */
        p_rec->bd_addr = p_keys->pid_key.identity_addr;
        /* combine DUMO device security record if needed */
        btm_consolidate_dev(p_rec);
        break;

      case BTM_LE_KEY_PCSRK:
        p_rec->ble.keys.pcsrk = p_keys->pcsrk_key.csrk;
        p_rec->ble.keys.srk_sec_level = p_keys->pcsrk_key.sec_level;
        p_rec->ble.keys.counter = p_keys->pcsrk_key.counter;
        p_rec->ble.key_type |= BTM_LE_KEY_PCSRK;
        p_rec->sec_flags |= BTM_SEC_LE_LINK_KEY_KNOWN;
        if (p_keys->pcsrk_key.sec_level == SMP_SEC_AUTHENTICATED)
          p_rec->sec_flags |= BTM_SEC_LE_LINK_KEY_AUTHED;
        else
          p_rec->sec_flags &= ~BTM_SEC_LE_LINK_KEY_AUTHED;

        BTM_TRACE_DEBUG(
            "BTM_LE_KEY_PCSRK key_type=0x%x sec_flags=0x%x sec_level=0x%x "
            "peer_counter=%d",
            p_rec->ble.key_type, p_rec->sec_flags,
            p_rec->ble.keys.srk_sec_level, p_rec->ble.keys.counter);
        break;

      case BTM_LE_KEY_LENC:
        p_rec->ble.keys.lltk = p_keys->lenc_key.ltk;
        p_rec->ble.keys.div = p_keys->lenc_key.div; /* update DIV */
        p_rec->ble.keys.sec_level = p_keys->lenc_key.sec_level;
        p_rec->ble.keys.key_size = p_keys->lenc_key.key_size;
        p_rec->ble.key_type |= BTM_LE_KEY_LENC;

        BTM_TRACE_DEBUG(
            "BTM_LE_KEY_LENC key_type=0x%x DIV=0x%x key_size=0x%x "
            "sec_level=0x%x",
            p_rec->ble.key_type, p_rec->ble.keys.div, p_rec->ble.keys.key_size,
            p_rec->ble.keys.sec_level);
        break;

      case BTM_LE_KEY_LCSRK: /* local CSRK has been delivered */
        p_rec->ble.keys.lcsrk = p_keys->lcsrk_key.csrk;
        p_rec->ble.keys.div = p_keys->lcsrk_key.div; /* update DIV */
        p_rec->ble.keys.local_csrk_sec_level = p_keys->lcsrk_key.sec_level;
        p_rec->ble.keys.local_counter = p_keys->lcsrk_key.counter;
        p_rec->ble.key_type |= BTM_LE_KEY_LCSRK;
        BTM_TRACE_DEBUG(
            "BTM_LE_KEY_LCSRK key_type=0x%x DIV=0x%x scrk_sec_level=0x%x "
            "local_counter=%d",
            p_rec->ble.key_type, p_rec->ble.keys.div,
            p_rec->ble.keys.local_csrk_sec_level,
            p_rec->ble.keys.local_counter);
        break;

      case BTM_LE_KEY_LID:
        p_rec->ble.key_type |= BTM_LE_KEY_LID;
        break;
      default:
        BTM_TRACE_WARNING("btm_sec_save_le_key (Bad key_type 0x%02x)",
                          key_type);
        return;
    }

    VLOG(1) << "BLE key type 0x" << loghex(key_type)
            << " updated for BDA: " << bd_addr << " (btm_sec_save_le_key)";

    /* Notify the application that one of the BLE keys has been updated
       If link key is in progress, it will get sent later.*/
    if (pass_to_application && btm_cb.api.p_le_callback) {
      cb_data.key.p_key_value = p_keys;
      cb_data.key.key_type = key_type;

      (*btm_cb.api.p_le_callback)(BTM_LE_KEY_EVT, bd_addr, &cb_data);
    }
    return;
  }

  LOG(WARNING) << "BLE key type 0x" << loghex(key_type)
               << " called for Unknown BDA or type: " << bd_addr
               << "(btm_sec_save_le_key)";

  if (p_rec) {
    BTM_TRACE_DEBUG("sec_flags=0x%x", p_rec->sec_flags);
  }
}

/*******************************************************************************
 *
 * Function         btm_ble_update_sec_key_size
 *
 * Description      update the current lin kencryption key size
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_update_sec_key_size(const RawAddress& bd_addr,
                                 uint8_t enc_key_size) {
  tBTM_SEC_DEV_REC* p_rec;

  BTM_TRACE_DEBUG("btm_ble_update_sec_key_size enc_key_size = %d",
                  enc_key_size);

  p_rec = btm_find_dev(bd_addr);
  if (p_rec != NULL) {
    p_rec->enc_key_size = enc_key_size;
  }
}

/*******************************************************************************
 *
 * Function         btm_ble_read_sec_key_size
 *
 * Description      update the current lin kencryption key size
 *
 * Returns          void
 *
 ******************************************************************************/
uint8_t btm_ble_read_sec_key_size(const RawAddress& bd_addr) {
  tBTM_SEC_DEV_REC* p_rec;

  p_rec = btm_find_dev(bd_addr);
  if (p_rec != NULL) {
    return p_rec->enc_key_size;
  } else
    return 0;
}

/*******************************************************************************
 *
 * Function         btm_ble_link_sec_check
 *
 * Description      Check BLE link security level match.
 *
 * Returns          true: check is OK and the *p_sec_req_act contain the action
 *
 ******************************************************************************/
void btm_ble_link_sec_check(const RawAddress& bd_addr,
                            tBTM_LE_AUTH_REQ auth_req,
                            tBTM_BLE_SEC_REQ_ACT* p_sec_req_act) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);
  uint8_t req_sec_level = BTM_LE_SEC_NONE, cur_sec_level = BTM_LE_SEC_NONE;

  BTM_TRACE_DEBUG("btm_ble_link_sec_check auth_req =0x%x", auth_req);

  if (p_dev_rec == NULL) {
    BTM_TRACE_ERROR("btm_ble_link_sec_check received for unknown device");
    return;
  }

  if (p_dev_rec->sec_state == BTM_SEC_STATE_ENCRYPTING ||
      p_dev_rec->sec_state == BTM_SEC_STATE_AUTHENTICATING) {
    /* race condition: discard the security request while central is encrypting
     * the link */
    *p_sec_req_act = BTM_BLE_SEC_REQ_ACT_DISCARD;
  } else {
    req_sec_level = BTM_LE_SEC_UNAUTHENTICATE;
    if (auth_req & BTM_LE_AUTH_REQ_MITM) {
      req_sec_level = BTM_LE_SEC_AUTHENTICATED;
    }

    BTM_TRACE_DEBUG("dev_rec sec_flags=0x%x", p_dev_rec->sec_flags);

    /* currently encrpted  */
    if (p_dev_rec->sec_flags & BTM_SEC_LE_ENCRYPTED) {
      if (p_dev_rec->sec_flags & BTM_SEC_LE_AUTHENTICATED)
        cur_sec_level = BTM_LE_SEC_AUTHENTICATED;
      else
        cur_sec_level = BTM_LE_SEC_UNAUTHENTICATE;
    } else /* unencrypted link */
    {
      /* if bonded, get the key security level */
      if (p_dev_rec->ble.key_type & BTM_LE_KEY_PENC)
        cur_sec_level = p_dev_rec->ble.keys.sec_level;
      else
        cur_sec_level = BTM_LE_SEC_NONE;
    }

    if (cur_sec_level >= req_sec_level) {
      /* To avoid re-encryption on an encrypted link for an equal condition
       * encryption */
      *p_sec_req_act = BTM_BLE_SEC_REQ_ACT_ENCRYPT;
    } else {
      /* start the pariring process to upgrade the keys*/
      *p_sec_req_act = BTM_BLE_SEC_REQ_ACT_PAIR;
    }
  }

  BTM_TRACE_DEBUG("cur_sec_level=%d req_sec_level=%d sec_req_act=%d",
                  cur_sec_level, req_sec_level, *p_sec_req_act);
}

/*******************************************************************************
 *
 * Function         btm_ble_set_encryption
 *
 * Description      This function is called to ensure that LE connection is
 *                  encrypted.  Should be called only on an open connection.
 *                  Typically only needed for connections that first want to
 *                  bring up unencrypted links, then later encrypt them.
 *
 * Returns          void
 *                  the local device ER is copied into er
 *
 ******************************************************************************/
tBTM_STATUS btm_ble_set_encryption(const RawAddress& bd_addr,
                                   tBTM_BLE_SEC_ACT sec_act,
                                   uint8_t link_role) {
  tBTM_STATUS cmd = BTM_NO_RESOURCES;
  tBTM_SEC_DEV_REC* p_rec = btm_find_dev(bd_addr);
  tBTM_BLE_SEC_REQ_ACT sec_req_act;
  tBTM_LE_AUTH_REQ auth_req;

  if (p_rec == NULL) {
    BTM_TRACE_WARNING(
        "btm_ble_set_encryption (NULL device record!! sec_act=0x%x", sec_act);
    return (BTM_WRONG_MODE);
  }

  BTM_TRACE_DEBUG("btm_ble_set_encryption sec_act=0x%x role_central=%d",
                  sec_act, p_rec->role_central);

  if (sec_act == BTM_BLE_SEC_ENCRYPT_MITM) {
    p_rec->security_required |= BTM_SEC_IN_MITM;
  }

  switch (sec_act) {
    case BTM_BLE_SEC_ENCRYPT:
      if (link_role == HCI_ROLE_CENTRAL) {
        /* start link layer encryption using the security info stored */
        cmd = btm_ble_start_encrypt(bd_addr, false, NULL);
        break;
      }
      /* if salve role then fall through to call SMP_Pair below which will send
         a sec_request to request the central to encrypt the link */
      FALLTHROUGH_INTENDED; /* FALLTHROUGH */
    case BTM_BLE_SEC_ENCRYPT_NO_MITM:
    case BTM_BLE_SEC_ENCRYPT_MITM:
      auth_req = (sec_act == BTM_BLE_SEC_ENCRYPT_NO_MITM)
                     ? SMP_AUTH_BOND
                     : (SMP_AUTH_BOND | SMP_AUTH_YN_BIT);
      btm_ble_link_sec_check(bd_addr, auth_req, &sec_req_act);
      if (sec_req_act == BTM_BLE_SEC_REQ_ACT_NONE ||
          sec_req_act == BTM_BLE_SEC_REQ_ACT_DISCARD) {
        BTM_TRACE_DEBUG("%s, no action needed. Ignore", __func__);
        cmd = BTM_SUCCESS;
        break;
      }
      if (link_role == HCI_ROLE_CENTRAL) {
        if (sec_req_act == BTM_BLE_SEC_REQ_ACT_ENCRYPT) {
          cmd = btm_ble_start_encrypt(bd_addr, false, NULL);
          break;
        }
      }

      if (SMP_Pair(bd_addr) == SMP_STARTED) {
        cmd = BTM_CMD_STARTED;
        p_rec->sec_state = BTM_SEC_STATE_AUTHENTICATING;
      }
      break;

    default:
      cmd = BTM_WRONG_MODE;
      break;
  }
  return cmd;
}

/*******************************************************************************
 *
 * Function         btm_ble_ltk_request
 *
 * Description      This function is called when encryption request is received
 *                  on a peripheral device.
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_ltk_request(uint16_t handle, uint8_t rand[8], uint16_t ediv) {
  tBTM_CB* p_cb = &btm_cb;
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev_by_handle(handle);

  BTM_TRACE_DEBUG("btm_ble_ltk_request");

  p_cb->ediv = ediv;

  memcpy(p_cb->enc_rand, rand, BT_OCTET8_LEN);

  if (p_dev_rec != NULL) {
    if (!smp_proc_ltk_request(p_dev_rec->bd_addr)) {
      btm_ble_ltk_request_reply(p_dev_rec->bd_addr, false, Octet16{0});
    }
  }
}

/** This function is called to start LE encryption.
 * Returns BTM_SUCCESS if encryption was started successfully
 */
tBTM_STATUS btm_ble_start_encrypt(const RawAddress& bda, bool use_stk,
                                  Octet16* p_stk) {
  tBTM_CB* p_cb = &btm_cb;
  tBTM_SEC_DEV_REC* p_rec = btm_find_dev(bda);
  BT_OCTET8 dummy_rand = {0};

  BTM_TRACE_DEBUG("btm_ble_start_encrypt");

  if (!p_rec) {
    BTM_TRACE_ERROR("Link is not active, can not encrypt!");
    return BTM_WRONG_MODE;
  }

  if (p_rec->sec_state == BTM_SEC_STATE_ENCRYPTING) {
    BTM_TRACE_WARNING("Link Encryption is active, Busy!");
    return BTM_BUSY;
  }

  p_cb->enc_handle = p_rec->ble_hci_handle;

  if (use_stk) {
    btsnd_hcic_ble_start_enc(p_rec->ble_hci_handle, dummy_rand, 0, *p_stk);
  } else if (p_rec->ble.key_type & BTM_LE_KEY_PENC) {
    btsnd_hcic_ble_start_enc(p_rec->ble_hci_handle, p_rec->ble.keys.rand,
                             p_rec->ble.keys.ediv, p_rec->ble.keys.pltk);
  } else {
    BTM_TRACE_ERROR("No key available to encrypt the link");
    return BTM_NO_RESOURCES;
  }

  if (p_rec->sec_state == BTM_SEC_STATE_IDLE)
    p_rec->sec_state = BTM_SEC_STATE_ENCRYPTING;

  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         btm_ble_link_encrypted
 *
 * Description      This function is called when LE link encrption status is
 *                  changed.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_link_encrypted(const RawAddress& bd_addr, uint8_t encr_enable) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);
  bool enc_cback;

  if (!p_dev_rec) {
    BTM_TRACE_WARNING(
        "btm_ble_link_encrypted (No Device Found!) encr_enable=%d",
        encr_enable);
    return;
  }

  BTM_TRACE_DEBUG("btm_ble_link_encrypted encr_enable=%d", encr_enable);

  enc_cback = (p_dev_rec->sec_state == BTM_SEC_STATE_ENCRYPTING);

  smp_link_encrypted(bd_addr, encr_enable);

  BTM_TRACE_DEBUG(" p_dev_rec->sec_flags=0x%x", p_dev_rec->sec_flags);

  if (encr_enable && p_dev_rec->enc_key_size == 0)
    p_dev_rec->enc_key_size = p_dev_rec->ble.keys.key_size;

  p_dev_rec->sec_state = BTM_SEC_STATE_IDLE;
  if (p_dev_rec->p_callback && enc_cback) {
    if (encr_enable)
      btm_sec_dev_rec_cback_event(p_dev_rec, BTM_SUCCESS, true);
    else if (p_dev_rec->sec_flags & ~BTM_SEC_LE_LINK_KEY_KNOWN) {
      btm_sec_dev_rec_cback_event(p_dev_rec, BTM_FAILED_ON_SECURITY, true);
    } else if (p_dev_rec->role_central)
      btm_sec_dev_rec_cback_event(p_dev_rec, BTM_ERR_PROCESSING, true);
  }
  /* to notify GATT to send data if any request is pending */
  gatt_notify_enc_cmpl(p_dev_rec->ble.pseudo_addr);
}

/*******************************************************************************
 *
 * Function         btm_ble_ltk_request_reply
 *
 * Description      This function is called to send a LTK request reply on a
 *                  peripheral
 *                  device.
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_ltk_request_reply(const RawAddress& bda, bool use_stk,
                               const Octet16& stk) {
  tBTM_SEC_DEV_REC* p_rec = btm_find_dev(bda);
  tBTM_CB* p_cb = &btm_cb;

  if (p_rec == NULL) {
    BTM_TRACE_ERROR("btm_ble_ltk_request_reply received for unknown device");
    return;
  }

  BTM_TRACE_DEBUG("btm_ble_ltk_request_reply");
  p_cb->enc_handle = p_rec->ble_hci_handle;
  p_cb->key_size = p_rec->ble.keys.key_size;

  BTM_TRACE_ERROR("key size = %d", p_rec->ble.keys.key_size);
  if (use_stk) {
    btsnd_hcic_ble_ltk_req_reply(btm_cb.enc_handle, stk);
  } else /* calculate LTK using peer device  */
  {
    if (p_rec->ble.key_type & BTM_LE_KEY_LENC)
      btsnd_hcic_ble_ltk_req_reply(btm_cb.enc_handle, p_rec->ble.keys.lltk);
    else
      btsnd_hcic_ble_ltk_req_neg_reply(btm_cb.enc_handle);
  }
}

/*******************************************************************************
 *
 * Function         btm_ble_io_capabilities_req
 *
 * Description      This function is called to handle SMP get IO capability
 *                  request.
 *
 * Returns          void
 *
 ******************************************************************************/
uint8_t btm_ble_io_capabilities_req(tBTM_SEC_DEV_REC* p_dev_rec,
                                    tBTM_LE_IO_REQ* p_data) {
  uint8_t callback_rc = BTM_SUCCESS;
  BTM_TRACE_DEBUG("btm_ble_io_capabilities_req");
  if (btm_cb.api.p_le_callback) {
    /* the callback function implementation may change the IO capability... */
    callback_rc = (*btm_cb.api.p_le_callback)(
        BTM_LE_IO_REQ_EVT, p_dev_rec->bd_addr, (tBTM_LE_EVT_DATA*)p_data);
  }
  if ((callback_rc == BTM_SUCCESS) || (BTM_OOB_UNKNOWN != p_data->oob_data)) {
#if (BTM_BLE_CONFORMANCE_TESTING == TRUE)
    if (btm_cb.devcb.keep_rfu_in_auth_req) {
      BTM_TRACE_DEBUG("btm_ble_io_capabilities_req keep_rfu_in_auth_req = %u",
                      btm_cb.devcb.keep_rfu_in_auth_req);
      p_data->auth_req &= BTM_LE_AUTH_REQ_MASK_KEEP_RFU;
      btm_cb.devcb.keep_rfu_in_auth_req = false;
    } else { /* default */
      p_data->auth_req &= BTM_LE_AUTH_REQ_MASK;
    }
#else
    p_data->auth_req &= BTM_LE_AUTH_REQ_MASK;
#endif

    BTM_TRACE_DEBUG(
        "btm_ble_io_capabilities_req 1: p_dev_rec->security_required = %d "
        "auth_req:%d",
        p_dev_rec->security_required, p_data->auth_req);
    BTM_TRACE_DEBUG(
        "btm_ble_io_capabilities_req 2: i_keys=0x%x r_keys=0x%x (bit 0-LTK "
        "1-IRK 2-CSRK)",
        p_data->init_keys, p_data->resp_keys);

    /* if authentication requires MITM protection, put on the mask */
    if (p_dev_rec->security_required & BTM_SEC_IN_MITM)
      p_data->auth_req |= BTM_LE_AUTH_REQ_MITM;

    if (!(p_data->auth_req & SMP_AUTH_BOND)) {
      BTM_TRACE_DEBUG("Non bonding: No keys should be exchanged");
      p_data->init_keys = 0;
      p_data->resp_keys = 0;
    }

    BTM_TRACE_DEBUG("btm_ble_io_capabilities_req 3: auth_req:%d",
                    p_data->auth_req);
    BTM_TRACE_DEBUG("btm_ble_io_capabilities_req 4: i_keys=0x%x r_keys=0x%x",
                    p_data->init_keys, p_data->resp_keys);

    BTM_TRACE_DEBUG(
        "btm_ble_io_capabilities_req 5: p_data->io_cap = %d auth_req:%d",
        p_data->io_cap, p_data->auth_req);

    /* remove MITM protection requirement if IO cap does not allow it */
    if ((p_data->io_cap == BTM_IO_CAP_NONE) && p_data->oob_data == SMP_OOB_NONE)
      p_data->auth_req &= ~BTM_LE_AUTH_REQ_MITM;

    if (!(p_data->auth_req & SMP_SC_SUPPORT_BIT)) {
      /* if Secure Connections are not supported then remove LK derivation,
      ** and keypress notifications.
      */
      BTM_TRACE_DEBUG(
          "%s-SC not supported -> No LK derivation, no keypress notifications",
          __func__);
      p_data->auth_req &= ~SMP_KP_SUPPORT_BIT;
      p_data->init_keys &= ~SMP_SEC_KEY_TYPE_LK;
      p_data->resp_keys &= ~SMP_SEC_KEY_TYPE_LK;
    }

    BTM_TRACE_DEBUG(
        "btm_ble_io_capabilities_req 6: IO_CAP:%d oob_data:%d auth_req:0x%02x",
        p_data->io_cap, p_data->oob_data, p_data->auth_req);
  }
  return callback_rc;
}

/*******************************************************************************
 *
 * Function         btm_ble_br_keys_req
 *
 * Description      This function is called to handle SMP request for keys sent
 *                  over BR/EDR.
 *
 * Returns          void
 *
 ******************************************************************************/
uint8_t btm_ble_br_keys_req(tBTM_SEC_DEV_REC* p_dev_rec,
                            tBTM_LE_IO_REQ* p_data) {
  uint8_t callback_rc = BTM_SUCCESS;
  BTM_TRACE_DEBUG("%s", __func__);
  if (btm_cb.api.p_le_callback) {
    /* the callback function implementation may change the IO capability... */
    callback_rc = (*btm_cb.api.p_le_callback)(
        BTM_LE_IO_REQ_EVT, p_dev_rec->bd_addr, (tBTM_LE_EVT_DATA*)p_data);
  }

  return callback_rc;
}

/*******************************************************************************
 *
 * Function         btm_ble_connected
 *
 * Description      This function is when a LE connection to the peer device is
 *                  establsihed
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_connected(const RawAddress& bda, uint16_t handle, uint8_t enc_mode,
                       uint8_t role, tBLE_ADDR_TYPE addr_type,
                       bool addr_matched) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bda);
  if (!p_dev_rec) {
    LOG_INFO("Creating new device record for new ble connection");
    p_dev_rec = btm_sec_alloc_dev(bda);
    if (p_dev_rec == nullptr) {
      LOG_WARN("Unable to create device record for new ble connection");
      return;
    }
  } else {
    LOG_INFO("Updating device record timestamp for existing ble connection");
    // TODO() Why is timestamp a counter ?
    p_dev_rec->timestamp = btm_cb.dev_rec_count++;
  }

  p_dev_rec->ble.ble_addr_type = addr_type;
  p_dev_rec->ble.pseudo_addr = bda;
  p_dev_rec->ble_hci_handle = handle;
  p_dev_rec->device_type |= BT_DEVICE_TYPE_BLE;
  p_dev_rec->role_central = (role == HCI_ROLE_CENTRAL) ? true : false;

  if (!addr_matched) {
    p_dev_rec->ble.active_addr_type = tBTM_SEC_BLE::BTM_BLE_ADDR_PSEUDO;
    if (p_dev_rec->ble.ble_addr_type == BLE_ADDR_RANDOM) {
      p_dev_rec->ble.cur_rand_addr = bda;
    }
  }
  btm_cb.ble_ctr_cb.inq_var.directed_conn = BTM_BLE_ADV_IND_EVT;
}

void btm_ble_connected_from_address_with_type(
    const tBLE_BD_ADDR& address_with_type, uint16_t handle, uint8_t enc_mode,
    uint8_t role, bool addr_matched) {
  btm_ble_connected(address_with_type.bda, handle, enc_mode, role,
                    address_with_type.type, addr_matched);
}

/*****************************************************************************
 *  Function        btm_proc_smp_cback
 *
 *  Description     This function is the SMP callback handler.
 *
 *****************************************************************************/
uint8_t btm_proc_smp_cback(tSMP_EVT event, const RawAddress& bd_addr,
                           tSMP_EVT_DATA* p_data) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev(bd_addr);
  uint8_t res = 0;

  BTM_TRACE_DEBUG("btm_proc_smp_cback event = %d", event);

  if (p_dev_rec != NULL) {
    switch (event) {
      case SMP_IO_CAP_REQ_EVT:
        btm_ble_io_capabilities_req(p_dev_rec,
                                    (tBTM_LE_IO_REQ*)&p_data->io_req);
        break;

      case SMP_BR_KEYS_REQ_EVT:
        btm_ble_br_keys_req(p_dev_rec, (tBTM_LE_IO_REQ*)&p_data->io_req);
        break;

      case SMP_PASSKEY_REQ_EVT:
      case SMP_PASSKEY_NOTIF_EVT:
      case SMP_OOB_REQ_EVT:
      case SMP_NC_REQ_EVT:
      case SMP_SC_OOB_REQ_EVT:
        p_dev_rec->sec_flags |= BTM_SEC_LE_AUTHENTICATED;
        FALLTHROUGH_INTENDED; /* FALLTHROUGH */

      case SMP_CONSENT_REQ_EVT:
      case SMP_SEC_REQUEST_EVT:
        if (event == SMP_SEC_REQUEST_EVT &&
            btm_cb.pairing_state != BTM_PAIR_STATE_IDLE) {
          BTM_TRACE_DEBUG("%s: Ignoring SMP Security request", __func__);
          break;
        }
        btm_cb.pairing_bda = bd_addr;
        if (event != SMP_CONSENT_REQ_EVT) {
          p_dev_rec->sec_state = BTM_SEC_STATE_AUTHENTICATING;
        }
        btm_cb.pairing_flags |= BTM_PAIR_FLAGS_LE_ACTIVE;
        FALLTHROUGH_INTENDED; /* FALLTHROUGH */

      case SMP_COMPLT_EVT:
        if (btm_cb.api.p_le_callback) {
          /* the callback function implementation may change the IO
           * capability... */
          BTM_TRACE_DEBUG("btm_cb.api.p_le_callback=0x%x",
                          btm_cb.api.p_le_callback);
          (*btm_cb.api.p_le_callback)(event, bd_addr,
                                      (tBTM_LE_EVT_DATA*)p_data);
        }

        if (event == SMP_COMPLT_EVT) {
          p_dev_rec = btm_find_dev(bd_addr);
          if (p_dev_rec == NULL) {
            BTM_TRACE_ERROR("%s: p_dev_rec is NULL", __func__);
            android_errorWriteLog(0x534e4554, "120612744");
            return 0;
          }
          BTM_TRACE_DEBUG(
              "evt=SMP_COMPLT_EVT before update sec_level=0x%x sec_flags=0x%x",
              p_data->cmplt.sec_level, p_dev_rec->sec_flags);

          res = (p_data->cmplt.reason == SMP_SUCCESS) ? BTM_SUCCESS
                                                      : BTM_ERR_PROCESSING;

          BTM_TRACE_DEBUG(
              "after update result=%d sec_level=0x%x sec_flags=0x%x", res,
              p_data->cmplt.sec_level, p_dev_rec->sec_flags);

          if (p_data->cmplt.is_pair_cancel &&
              btm_cb.api.p_bond_cancel_cmpl_callback) {
            BTM_TRACE_DEBUG("Pairing Cancel completed");
            (*btm_cb.api.p_bond_cancel_cmpl_callback)(BTM_SUCCESS);
          }
#if (BTM_BLE_CONFORMANCE_TESTING == TRUE)
          if (res != BTM_SUCCESS) {
            if (!btm_cb.devcb.no_disc_if_pair_fail &&
                p_data->cmplt.reason != SMP_CONN_TOUT) {
              BTM_TRACE_DEBUG("Pairing failed - prepare to remove ACL");
              l2cu_start_post_bond_timer(p_dev_rec->ble_hci_handle);
            } else {
              BTM_TRACE_DEBUG("Pairing failed - Not Removing ACL");
              p_dev_rec->sec_state = BTM_SEC_STATE_IDLE;
            }
          }
#else
          if (res != BTM_SUCCESS && p_data->cmplt.reason != SMP_CONN_TOUT) {
            BTM_TRACE_DEBUG("Pairing failed - prepare to remove ACL");
            l2cu_start_post_bond_timer(p_dev_rec->ble_hci_handle);
          }
#endif

          BTM_TRACE_DEBUG(
              "btm_cb pairing_state=%x pairing_flags=%x pin_code_len=%x",
              btm_cb.pairing_state, btm_cb.pairing_flags, btm_cb.pin_code_len);
          VLOG(1) << "btm_cb.pairing_bda: " << btm_cb.pairing_bda;

          /* Reset btm state only if the callback address matches pairing
           * address*/
          if (bd_addr == btm_cb.pairing_bda) {
            btm_cb.pairing_bda = RawAddress::kAny;
            btm_cb.pairing_state = BTM_PAIR_STATE_IDLE;
            btm_cb.pairing_flags = 0;
          }

          if (res == BTM_SUCCESS) {
            p_dev_rec->sec_state = BTM_SEC_STATE_IDLE;
            /* add all bonded device into resolving list if IRK is available*/
            btm_ble_resolving_list_load_dev(p_dev_rec);
          }

          btm_sec_dev_rec_cback_event(p_dev_rec, res, true);
        }
        break;

      default:
        BTM_TRACE_DEBUG("unknown event = %d", event);
        break;
    }
  } else {
    BTM_TRACE_ERROR("btm_proc_smp_cback received for unknown device");
  }

  return 0;
}

/*******************************************************************************
 *
 * Function         BTM_BleDataSignature
 *
 * Description      This function is called to sign the data using AES128 CMAC
 *                  algorith.
 *
 * Parameter        bd_addr: target device the data to be signed for.
 *                  p_text: singing data
 *                  len: length of the data to be signed.
 *                  signature: output parameter where data signature is going to
 *                             be stored.
 *
 * Returns          true if signing sucessul, otherwise false.
 *
 ******************************************************************************/
bool BTM_BleDataSignature(const RawAddress& bd_addr, uint8_t* p_text,
                          uint16_t len, BLE_SIGNATURE signature) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleDataSignature(bd_addr, p_text, len,
                                                 signature);
  }
  tBTM_SEC_DEV_REC* p_rec = btm_find_dev(bd_addr);

  BTM_TRACE_DEBUG("%s", __func__);
  if (p_rec == NULL) {
    BTM_TRACE_ERROR("%s-data signing can not be done from unknown device",
                    __func__);
    return false;
  }

  uint8_t* p_mac = (uint8_t*)signature;
  uint8_t* pp;
  uint8_t* p_buf = (uint8_t*)osi_malloc(len + 4);

  BTM_TRACE_DEBUG("%s-Start to generate Local CSRK", __func__);
  pp = p_buf;
  /* prepare plain text */
  if (p_text) {
    memcpy(p_buf, p_text, len);
    pp = (p_buf + len);
  }

  UINT32_TO_STREAM(pp, p_rec->ble.keys.local_counter);
  UINT32_TO_STREAM(p_mac, p_rec->ble.keys.local_counter);

  crypto_toolbox::aes_cmac(p_rec->ble.keys.lcsrk, p_buf, (uint16_t)(len + 4),
                           BTM_CMAC_TLEN_SIZE, p_mac);
  btm_ble_increment_sign_ctr(bd_addr, true);

  BTM_TRACE_DEBUG("%s p_mac = %d", __func__, p_mac);
  BTM_TRACE_DEBUG(
      "p_mac[0] = 0x%02x p_mac[1] = 0x%02x p_mac[2] = 0x%02x p_mac[3] = "
      "0x%02x",
      *p_mac, *(p_mac + 1), *(p_mac + 2), *(p_mac + 3));
  BTM_TRACE_DEBUG(
      "p_mac[4] = 0x%02x p_mac[5] = 0x%02x p_mac[6] = 0x%02x p_mac[7] = "
      "0x%02x",
      *(p_mac + 4), *(p_mac + 5), *(p_mac + 6), *(p_mac + 7));
  osi_free(p_buf);
  return true;
}

/*******************************************************************************
 *
 * Function         BTM_BleVerifySignature
 *
 * Description      This function is called to verify the data signature
 *
 * Parameter        bd_addr: target device the data to be signed for.
 *                  p_orig:  original data before signature.
 *                  len: length of the signing data
 *                  counter: counter used when doing data signing
 *                  p_comp: signature to be compared against.

 * Returns          true if signature verified correctly; otherwise false.
 *
 ******************************************************************************/
bool BTM_BleVerifySignature(const RawAddress& bd_addr, uint8_t* p_orig,
                            uint16_t len, uint32_t counter, uint8_t* p_comp) {
  if (bluetooth::shim::is_gd_shim_enabled()) {
    return bluetooth::shim::BTM_BleVerifySignature(bd_addr, p_orig, len,
                                                   counter, p_comp);
  }
  bool verified = false;
  tBTM_SEC_DEV_REC* p_rec = btm_find_dev(bd_addr);
  uint8_t p_mac[BTM_CMAC_TLEN_SIZE];

  if (p_rec == NULL || (p_rec && !(p_rec->ble.key_type & BTM_LE_KEY_PCSRK))) {
    BTM_TRACE_ERROR("can not verify signature for unknown device");
  } else if (counter < p_rec->ble.keys.counter) {
    BTM_TRACE_ERROR("signature received with out dated sign counter");
  } else if (p_orig == NULL) {
    BTM_TRACE_ERROR("No signature to verify");
  } else {
    BTM_TRACE_DEBUG("%s rcv_cnt=%d >= expected_cnt=%d", __func__, counter,
                    p_rec->ble.keys.counter);

    crypto_toolbox::aes_cmac(p_rec->ble.keys.pcsrk, p_orig, len,
                             BTM_CMAC_TLEN_SIZE, p_mac);
    if (memcmp(p_mac, p_comp, BTM_CMAC_TLEN_SIZE) == 0) {
      btm_ble_increment_sign_ctr(bd_addr, false);
      verified = true;
    }
  }
  return verified;
}

/*******************************************************************************
 *  Utility functions for LE device IR/ER generation
 ******************************************************************************/
/** This function is to notify application new keys have been generated. */
static void btm_notify_new_key(uint8_t key_type) {
  tBTM_BLE_LOCAL_KEYS* p_local_keys = NULL;

  BTM_TRACE_DEBUG("btm_notify_new_key key_type=%d", key_type);

  if (btm_cb.api.p_le_key_callback) {
    switch (key_type) {
      case BTM_BLE_KEY_TYPE_ID:
        BTM_TRACE_DEBUG("BTM_BLE_KEY_TYPE_ID");
        p_local_keys = (tBTM_BLE_LOCAL_KEYS*)&btm_cb.devcb.id_keys;
        break;

      case BTM_BLE_KEY_TYPE_ER:
        BTM_TRACE_DEBUG("BTM_BLE_KEY_TYPE_ER");
        p_local_keys =
            (tBTM_BLE_LOCAL_KEYS*)&btm_cb.devcb.ble_encryption_key_value;
        break;

      default:
        BTM_TRACE_ERROR("unknown key type: %d", key_type);
        break;
    }
    if (p_local_keys != NULL)
      (*btm_cb.api.p_le_key_callback)(key_type, p_local_keys);
  }
}

/** implementation of btm_ble_reset_id */
static void btm_ble_reset_id_impl(const Octet16& rand1, const Octet16& rand2) {
  /* Regenerate Identity Root */
  btm_cb.devcb.id_keys.ir = rand1;
  uint8_t btm_ble_dhk_pt = 0x03;

  /* generate DHK= Eir({0x03, 0x00, 0x00 ...}) */
  btm_cb.devcb.id_keys.dhk =
      crypto_toolbox::aes_128(btm_cb.devcb.id_keys.ir, &btm_ble_dhk_pt, 1);

  uint8_t btm_ble_irk_pt = 0x01;
  /* IRK = D1(IR, 1) */
  btm_cb.devcb.id_keys.irk =
      crypto_toolbox::aes_128(btm_cb.devcb.id_keys.ir, &btm_ble_irk_pt, 1);

  btm_notify_new_key(BTM_BLE_KEY_TYPE_ID);

  /* if privacy is enabled, new RPA should be calculated */
  if (btm_cb.ble_ctr_cb.privacy_mode != BTM_PRIVACY_NONE) {
    btm_gen_resolvable_private_addr(base::Bind(&btm_gen_resolve_paddr_low));
  }

  /* proceed generate ER */
  btm_cb.devcb.ble_encryption_key_value = rand2;
  btm_notify_new_key(BTM_BLE_KEY_TYPE_ER);
}

struct reset_id_data {
  Octet16 rand1;
  Octet16 rand2;
};

/** This function is called to reset LE device identity. */
void btm_ble_reset_id(void) {
  BTM_TRACE_DEBUG("btm_ble_reset_id");

  /* In order to reset identity, we need four random numbers. Make four nested
   * calls to generate them first, then proceed to perform the actual reset in
   * btm_ble_reset_id_impl. */
  btsnd_hcic_ble_rand(base::Bind([](BT_OCTET8 rand) {
    reset_id_data tmp;
    memcpy(tmp.rand1.data(), rand, BT_OCTET8_LEN);
    btsnd_hcic_ble_rand(base::Bind(
        [](reset_id_data tmp, BT_OCTET8 rand) {
          memcpy(tmp.rand1.data() + 8, rand, BT_OCTET8_LEN);
          btsnd_hcic_ble_rand(base::Bind(
              [](reset_id_data tmp, BT_OCTET8 rand) {
                memcpy(tmp.rand2.data(), rand, BT_OCTET8_LEN);
                btsnd_hcic_ble_rand(base::Bind(
                    [](reset_id_data tmp, BT_OCTET8 rand) {
                      memcpy(tmp.rand2.data() + 8, rand, BT_OCTET8_LEN);
                      // when all random numbers are ready, do the actual reset.
                      btm_ble_reset_id_impl(tmp.rand1, tmp.rand2);
                    },
                    tmp));
              },
              tmp));
        },
        tmp));
  }));
}

/* This function set a random address to local controller. It also temporarily
 * disable scans and adv before sending the command to the controller. */
void btm_ble_set_random_address(const RawAddress& random_bda) {
  tBTM_LE_RANDOM_CB* p_cb = &btm_cb.ble_ctr_cb.addr_mgnt_cb;
  tBTM_BLE_CB* p_ble_cb = &btm_cb.ble_ctr_cb;
  bool adv_mode = btm_cb.ble_ctr_cb.inq_var.adv_mode;

  BTM_TRACE_DEBUG("%s", __func__);

  if (adv_mode == BTM_BLE_ADV_ENABLE)
    btsnd_hcic_ble_set_adv_enable(BTM_BLE_ADV_DISABLE);
  if (p_ble_cb->is_ble_scan_active()) {
    btm_ble_stop_scan();
  }
  btm_ble_suspend_bg_conn();

  p_cb->private_addr = random_bda;
  btsnd_hcic_ble_set_random_addr(p_cb->private_addr);

  if (adv_mode == BTM_BLE_ADV_ENABLE)
    btsnd_hcic_ble_set_adv_enable(BTM_BLE_ADV_ENABLE);
  if (p_ble_cb->is_ble_scan_active()) {
    btm_ble_start_scan();
  }
  btm_ble_resume_bg_conn();
}

/*******************************************************************************
 *
 * Function         btm_ble_get_acl_remote_addr
 *
 * Description      This function reads the active remote address used for the
 *                  connection.
 *
 * Returns          success return true, otherwise false.
 *
 ******************************************************************************/
bool btm_ble_get_acl_remote_addr(uint16_t hci_handle, RawAddress& conn_addr,
                                 tBLE_ADDR_TYPE* p_addr_type) {
  tBTM_SEC_DEV_REC* p_dev_rec = btm_find_dev_by_handle(hci_handle);
  if (p_dev_rec == nullptr) {
    LOG_WARN("Unable to find security device record hci_handle:%hu",
             hci_handle);
    // TODO Release acl resource
    return false;
  }

  bool st = true;

  switch (p_dev_rec->ble.active_addr_type) {
    case tBTM_SEC_BLE::BTM_BLE_ADDR_PSEUDO:
      conn_addr = p_dev_rec->bd_addr;
      *p_addr_type = p_dev_rec->ble.ble_addr_type;
      break;

    case tBTM_SEC_BLE::BTM_BLE_ADDR_RRA:
      conn_addr = p_dev_rec->ble.cur_rand_addr;
      *p_addr_type = BLE_ADDR_RANDOM;
      break;

    case tBTM_SEC_BLE::BTM_BLE_ADDR_STATIC:
      conn_addr = p_dev_rec->ble.identity_address_with_type.bda;
      *p_addr_type = p_dev_rec->ble.identity_address_with_type.type;
      break;

    default:
      LOG_WARN("Unable to find record with active address type: %d",
               p_dev_rec->ble.active_addr_type);
      st = false;
      break;
  }
  return st;
}

#if BTM_BLE_CONFORMANCE_TESTING == TRUE
/*******************************************************************************
 *
 * Function         btm_ble_set_no_disc_if_pair_fail
 *
 * Description      This function indicates whether no disconnect of the ACL
 *                  should be used if pairing failed
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_set_no_disc_if_pair_fail(bool disable_disc) {
  BTM_TRACE_DEBUG("btm_ble_set_disc_enable_if_pair_fail disable_disc=%d",
                  disable_disc);
  btm_cb.devcb.no_disc_if_pair_fail = disable_disc;
}

/*******************************************************************************
 *
 * Function         btm_ble_set_test_mac_value
 *
 * Description      This function set test MAC value
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_set_test_mac_value(bool enable, uint8_t* p_test_mac_val) {
  BTM_TRACE_DEBUG("btm_ble_set_test_mac_value enable=%d", enable);
  btm_cb.devcb.enable_test_mac_val = enable;
  memcpy(btm_cb.devcb.test_mac, p_test_mac_val, BT_OCTET8_LEN);
}

/*******************************************************************************
 *
 * Function         btm_ble_set_test_local_sign_cntr_value
 *
 * Description      This function set test local sign counter value
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_set_test_local_sign_cntr_value(bool enable,
                                            uint32_t test_local_sign_cntr) {
  BTM_TRACE_DEBUG(
      "btm_ble_set_test_local_sign_cntr_value enable=%d local_sign_cntr=%d",
      enable, test_local_sign_cntr);
  btm_cb.devcb.enable_test_local_sign_cntr = enable;
  btm_cb.devcb.test_local_sign_cntr = test_local_sign_cntr;
}

/*******************************************************************************
 *
 * Function         btm_ble_set_keep_rfu_in_auth_req
 *
 * Description      This function indicates if RFU bits have to be kept as is
 *                  (by default they have to be set to 0 by the sender).
 *
 * Returns          void
 *
 ******************************************************************************/
void btm_ble_set_keep_rfu_in_auth_req(bool keep_rfu) {
  BTM_TRACE_DEBUG("btm_ble_set_keep_rfu_in_auth_req keep_rfus=%d", keep_rfu);
  btm_cb.devcb.keep_rfu_in_auth_req = keep_rfu;
}

#endif /* BTM_BLE_CONFORMANCE_TESTING */
