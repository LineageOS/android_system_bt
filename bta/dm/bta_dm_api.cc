/******************************************************************************
 *
 *  Copyright 2003-2014 Broadcom Corporation
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
 *  This is the API implementation file for the BTA device manager.
 *
 ******************************************************************************/

#include <base/bind.h>
#include <vector>

#include "bt_target.h"  // Must be first to define build configuration

#include "bta/dm/bta_dm_int.h"
#include "osi/include/allocator.h"
#include "stack/btm/btm_sec.h"
#include "stack/include/btm_api.h"
#include "stack/include/btu.h"  // do_in_main_thread
#include "types/bluetooth/uuid.h"
#include "types/raw_address.h"

using bluetooth::Uuid;

/*****************************************************************************
 *  Constants
 ****************************************************************************/

static const tBTA_SYS_REG bta_dm_search_reg = {bta_dm_search_sm_execute,
                                               bta_dm_search_sm_disable};

void BTA_dm_init() {
  bta_sys_register(BTA_ID_DM_SEARCH, &bta_dm_search_reg);
  /* if UUID list is not provided as static data */
  bta_sys_eir_register(bta_dm_eir_update_uuid);
  bta_sys_cust_eir_register(bta_dm_eir_update_cust_uuid);
}

/** Enables bluetooth device under test mode */
void BTA_EnableTestMode(void) {
  do_in_main_thread(FROM_HERE,
                    base::Bind(base::IgnoreResult(BTM_EnableTestMode)));
}

/** This function sets the Bluetooth name of local device */
void BTA_DmSetDeviceName(char* p_name) {
  std::vector<uint8_t> name(BD_NAME_LEN + 1);
  strlcpy((char*)name.data(), p_name, BD_NAME_LEN + 1);

  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_set_dev_name, name));
}

/*******************************************************************************
 *
 * Function         BTA_DmSearch
 *
 * Description      This function searches for peer Bluetooth devices. It
 *                  performs an inquiry and gets the remote name for devices.
 *                  Service discovery is done if services is non zero
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmSearch(tBTA_DM_SEARCH_CBACK* p_cback, bool is_bonding_or_sdp) {
  tBTA_DM_API_SEARCH* p_msg =
      (tBTA_DM_API_SEARCH*)osi_calloc(sizeof(tBTA_DM_API_SEARCH));

  /* Queue request if a device is bonding or performing service discovery */
  if (is_bonding_or_sdp) {
    p_msg->hdr.event = BTA_DM_API_QUEUE_SEARCH_EVT;
  } else {
    p_msg->hdr.event = BTA_DM_API_SEARCH_EVT;
  }
  p_msg->p_cback = p_cback;

  bta_sys_sendmsg(p_msg);
}

/*******************************************************************************
 *
 * Function         BTA_DmSearchCancel
 *
 * Description      This function  cancels a search initiated by BTA_DmSearch
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmSearchCancel(void) {
  bta_dm_search_clear_queue();

  switch (bta_dm_search_get_state()) {
    case BTA_DM_SEARCH_IDLE:
      bta_dm_search_cancel_notify();
      break;
    case BTA_DM_SEARCH_ACTIVE:
      bta_dm_search_set_state(BTA_DM_SEARCH_CANCELLING);
      bta_dm_search_cancel();
      break;
    case BTA_DM_SEARCH_CANCELLING:
      bta_dm_search_cancel_notify();
      break;
    case BTA_DM_DISCOVER_ACTIVE:
      bta_dm_search_set_state(BTA_DM_SEARCH_CANCELLING);
      bta_dm_search_cancel_notify();
      break;
  }
}

/*******************************************************************************
 *
 * Function         BTA_DmDiscover
 *
 * Description      This function does service discovery for services of a
 *                  peer device
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmDiscover(const RawAddress& bd_addr, tBTA_DM_SEARCH_CBACK* p_cback,
                    tBT_TRANSPORT transport, bool is_bonding_or_sdp) {
  tBTA_DM_API_DISCOVER* p_msg =
      (tBTA_DM_API_DISCOVER*)osi_calloc(sizeof(tBTA_DM_API_DISCOVER));

  if (is_bonding_or_sdp) {
    p_msg->hdr.event = BTA_DM_API_QUEUE_DISCOVER_EVT;
  } else {
    p_msg->hdr.event = BTA_DM_API_DISCOVER_EVT;
  }
  p_msg->bd_addr = bd_addr;
  p_msg->transport = transport;
  p_msg->p_cback = p_cback;

  bta_sys_sendmsg(p_msg);
}

/** This function initiates a bonding procedure with a peer device */
void BTA_DmBond(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                tBT_TRANSPORT transport, int device_type) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_bond, bd_addr, addr_type,
                                          transport, device_type));
}

/** This function cancels the bonding procedure with a peer device
 */
void BTA_DmBondCancel(const RawAddress& bd_addr) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_bond_cancel, bd_addr));
}

/*******************************************************************************
 *
 * Function         BTA_DmPinReply
 *
 * Description      This function provides a pincode for a remote device when
 *                  one is requested by DM through BTA_DM_PIN_REQ_EVT
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmPinReply(const RawAddress& bd_addr, bool accept, uint8_t pin_len,
                    uint8_t* p_pin) {
  std::unique_ptr<tBTA_DM_API_PIN_REPLY> msg =
      std::make_unique<tBTA_DM_API_PIN_REPLY>();

  msg->bd_addr = bd_addr;
  msg->accept = accept;
  if (accept) {
    msg->pin_len = pin_len;
    memcpy(msg->p_pin, p_pin, pin_len);
  }

  do_in_main_thread(FROM_HERE,
                    base::Bind(bta_dm_pin_reply, base::Passed(&msg)));
}

/*******************************************************************************
 *
 * Function         BTA_DmLocalOob
 *
 * Description      This function retrieves the OOB data from local controller.
 *                  The result is reported by:
 *                  - bta_dm_co_loc_oob_ext() if device supports secure
 *                    connections (SC)
 *                  - bta_dm_co_loc_oob() if device doesn't support SC
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmLocalOob(void) {
  do_in_main_thread(FROM_HERE, base::Bind(BTM_ReadLocalOobData));
}

/*******************************************************************************
 *
 * Function         BTA_DmConfirm
 *
 * Description      This function accepts or rejects the numerical value of the
 *                  Simple Pairing process on BTA_DM_SP_CFM_REQ_EVT
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmConfirm(const RawAddress& bd_addr, bool accept) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_confirm, bd_addr, accept));
}

/*******************************************************************************
 *
 * Function         BTA_DmAddDevice
 *
 * Description      This function adds a device to the security database list of
 *                  peer device
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmAddDevice(const RawAddress& bd_addr, DEV_CLASS dev_class,
                     const LinkKey& link_key, uint8_t key_type,
                     uint8_t pin_length) {
  std::unique_ptr<tBTA_DM_API_ADD_DEVICE> msg =
      std::make_unique<tBTA_DM_API_ADD_DEVICE>();

  msg->bd_addr = bd_addr;
  msg->link_key_known = true;
  msg->key_type = key_type;
  msg->link_key = link_key;

  /* Load device class if specified */
  if (dev_class) {
    msg->dc_known = true;
    memcpy(msg->dc, dev_class, DEV_CLASS_LEN);
  }

  memset(msg->bd_name, 0, BD_NAME_LEN + 1);
  msg->pin_length = pin_length;

  do_in_main_thread(FROM_HERE,
                    base::Bind(bta_dm_add_device, base::Passed(&msg)));
}

/** This function removes a device fromthe security database list of peer
 * device. It manages unpairing even while connected */
tBTA_STATUS BTA_DmRemoveDevice(const RawAddress& bd_addr) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_remove_device, bd_addr));
  return BTA_SUCCESS;
}

/*******************************************************************************
 *
 * Function         BTA_GetEirService
 *
 * Description      This function is called to get BTA service mask from EIR.
 *
 * Parameters       p_eir - pointer of EIR significant part
 *                  p_services - return the BTA service mask
 *
 * Returns          None
 *
 ******************************************************************************/
extern const uint16_t bta_service_id_to_uuid_lkup_tbl[];
void BTA_GetEirService(uint8_t* p_eir, size_t eir_len,
                       tBTA_SERVICE_MASK* p_services) {
  uint8_t xx, yy;
  uint8_t num_uuid, max_num_uuid = 32;
  uint8_t uuid_list[32 * Uuid::kNumBytes16];
  uint16_t* p_uuid16 = (uint16_t*)uuid_list;
  tBTA_SERVICE_MASK mask;

  BTM_GetEirUuidList(p_eir, eir_len, Uuid::kNumBytes16, &num_uuid, uuid_list,
                     max_num_uuid);
  for (xx = 0; xx < num_uuid; xx++) {
    mask = 1;
    for (yy = 0; yy < BTA_MAX_SERVICE_ID; yy++) {
      if (*(p_uuid16 + xx) == bta_service_id_to_uuid_lkup_tbl[yy]) {
        *p_services |= mask;
        break;
      }
      mask <<= 1;
    }

    /* for HSP v1.2 only device */
    if (*(p_uuid16 + xx) == UUID_SERVCLASS_HEADSET_HS)
      *p_services |= BTA_HSP_SERVICE_MASK;

    if (*(p_uuid16 + xx) == UUID_SERVCLASS_HDP_SOURCE)
      *p_services |= BTA_HL_SERVICE_MASK;

    if (*(p_uuid16 + xx) == UUID_SERVCLASS_HDP_SINK)
      *p_services |= BTA_HL_SERVICE_MASK;
  }
}

/*******************************************************************************
 *
 * Function         BTA_AddEirUuid
 *
 * Description      Request to add a service class UID to the local
 *                  device's EIR data.
 *
 * Parameters       uuid16 - The service class UUID you wish to add
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_AddEirUuid(uint16_t uuid16) {
  APPL_TRACE_API("%s: %d", __func__, uuid16);
  bta_sys_add_uuid(uuid16);
}

/*******************************************************************************
 *
 * Function         BTA_RemoveEirUuid
 *
 * Description      Request to remove a service class UID from the local
 *                  device's EIR data.
 *
 * Parameters       uuid16 - The service class UUID you wish to remove
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_RemoveEirUuid(uint16_t uuid16) {
  APPL_TRACE_API("%s: %d", __func__, uuid16);
  bta_sys_remove_uuid(uuid16);
}

/*******************************************************************************
 *
 * Function         BTA_DmGetConnectionState
 *
 * Description      Returns whether the remote device is currently connected.
 *
 * Returns          0 if the device is NOT connected.
 *
 ******************************************************************************/
bool BTA_DmGetConnectionState(const RawAddress& bd_addr) {
  tBTA_DM_PEER_DEVICE* p_dev = bta_dm_find_peer_device(bd_addr);
  return (p_dev && p_dev->conn_state == BTA_DM_CONNECTED);
}

/*******************************************************************************
 *                   Device Identification (DI) Server Functions
 ******************************************************************************/
/*******************************************************************************
 *
 * Function         BTA_DmSetLocalDiRecord
 *
 * Description      This function adds a DI record to the local SDP database.
 *
 * Returns          BTA_SUCCESS if record set sucessfully, otherwise error code.
 *
 ******************************************************************************/
tBTA_STATUS BTA_DmSetLocalDiRecord(tSDP_DI_RECORD* p_device_info,
                                   uint32_t* p_handle) {
  tBTA_STATUS status = BTA_FAILURE;

  if (bta_dm_di_cb.di_num < BTA_DI_NUM_MAX) {
    if (SDP_SetLocalDiRecord((tSDP_DI_RECORD*)p_device_info, p_handle) ==
        SDP_SUCCESS) {
      if (!p_device_info->primary_record) {
        bta_dm_di_cb.di_handle[bta_dm_di_cb.di_num] = *p_handle;
        bta_dm_di_cb.di_num++;
      }

      bta_sys_add_uuid(UUID_SERVCLASS_PNP_INFORMATION);
      status = BTA_SUCCESS;
    }
  }

  return status;
}

/*******************************************************************************
 *
 * Function         BTA_DmAddBleKey
 *
 * Description      Add/modify LE device information.  This function will be
 *                  normally called during host startup to restore all required
 *                  information stored in the NVRAM.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  p_le_key         - LE key values.
 *                  key_type         - LE SMP key type.
 *
 * Returns          BTA_SUCCESS if successful
 *                  BTA_FAIL if operation failed.
 *
 ******************************************************************************/
void BTA_DmAddBleKey(const RawAddress& bd_addr, tBTA_LE_KEY_VALUE* p_le_key,
                     tBTM_LE_KEY_TYPE key_type) {
  do_in_main_thread(
      FROM_HERE, base::Bind(bta_dm_add_blekey, bd_addr, *p_le_key, key_type));
}

/*******************************************************************************
 *
 * Function         BTA_DmAddBleDevice
 *
 * Description      Add a BLE device.  This function will be normally called
 *                  during host startup to restore all required information
 *                  for a LE device stored in the NVRAM.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  dev_type         - Remote device's device type.
 *                  addr_type        - LE device address type.
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmAddBleDevice(const RawAddress& bd_addr, tBLE_ADDR_TYPE addr_type,
                        tBT_DEVICE_TYPE dev_type) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_add_ble_device, bd_addr,
                                          addr_type, dev_type));
}

/*******************************************************************************
 *
 * Function         BTA_DmBlePasskeyReply
 *
 * Description      Send BLE SMP passkey reply.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  accept           - passkey entry sucessful or declined.
 *                  passkey          - passkey value, must be a 6 digit number,
 *                                     can be lead by 0.
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmBlePasskeyReply(const RawAddress& bd_addr, bool accept,
                           uint32_t passkey) {
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_ble_passkey_reply, bd_addr,
                                          accept, accept ? passkey : 0));
}

/*******************************************************************************
 *
 * Function         BTA_DmBleConfirmReply
 *
 * Description      Send BLE SMP SC user confirmation reply.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  accept           - numbers to compare are the same or
 *                                     different.
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmBleConfirmReply(const RawAddress& bd_addr, bool accept) {
  do_in_main_thread(FROM_HERE,
                    base::Bind(bta_dm_ble_confirm_reply, bd_addr, accept));
}

/*******************************************************************************
 *
 * Function         BTA_DmBleSecurityGrant
 *
 * Description      Grant security request access.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  res              - security grant status.
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmBleSecurityGrant(const RawAddress& bd_addr,
                            tBTA_DM_BLE_SEC_GRANT res) {
  do_in_main_thread(FROM_HERE, base::Bind(BTM_SecurityGrant, bd_addr, res));
}

/*******************************************************************************
 *
 * Function         BTA_DmSetBlePrefConnParams
 *
 * Description      This function is called to set the preferred connection
 *                  parameters when default connection parameter is not desired.
 *
 * Parameters:      bd_addr          - BD address of the peripheral
 *                  scan_interval    - scan interval
 *                  scan_window      - scan window
 *                  min_conn_int     - minimum preferred connection interval
 *                  max_conn_int     - maximum preferred connection interval
 *                  peripheral_latency    - preferred peripheral latency
 *                  supervision_tout - preferred supervision timeout
 *
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmSetBlePrefConnParams(const RawAddress& bd_addr,
                                uint16_t min_conn_int, uint16_t max_conn_int,
                                uint16_t peripheral_latency,
                                uint16_t supervision_tout) {
  do_in_main_thread(
      FROM_HERE,
      base::Bind(bta_dm_ble_set_conn_params, bd_addr, min_conn_int,
                 max_conn_int, peripheral_latency, supervision_tout));
}

/*******************************************************************************
 *
 * Function         BTA_DmBleUpdateConnectionParam
 *
 * Description      Update connection parameters, can only be used when
 *                  connection is up.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  min_int   -     minimum connection interval,
 *                                  [0x0004 ~ 0x4000]
 *                  max_int   -     maximum connection interval,
 *                                  [0x0004 ~ 0x4000]
 *                  latency   -     peripheral latency [0 ~ 500]
 *                  timeout   -     supervision timeout [0x000a ~ 0xc80]
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmBleUpdateConnectionParams(const RawAddress& bd_addr,
                                     uint16_t min_int, uint16_t max_int,
                                     uint16_t latency, uint16_t timeout,
                                     uint16_t min_ce_len, uint16_t max_ce_len) {
  do_in_main_thread(
      FROM_HERE, base::Bind(bta_dm_ble_update_conn_params, bd_addr, min_int,
                            max_int, latency, timeout, min_ce_len, max_ce_len));
}

/*******************************************************************************
 *
 * Function         BTA_DmBleConfigLocalPrivacy
 *
 * Description      Enable/disable privacy on the local device
 *
 * Parameters:      privacy_enable   - enable/disabe privacy on remote device.
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmBleConfigLocalPrivacy(bool privacy_enable) {
#if (BLE_PRIVACY_SPT == TRUE)
  do_in_main_thread(
      FROM_HERE, base::Bind(bta_dm_ble_config_local_privacy, privacy_enable));
#else
  UNUSED(privacy_enable);
#endif
}

/*******************************************************************************
 *
 * Function         BTA_DmBleGetEnergyInfo
 *
 * Description      This function is called to obtain the energy info
 *
 * Parameters       p_cmpl_cback - Command complete callback
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmBleGetEnergyInfo(tBTA_BLE_ENERGY_INFO_CBACK* p_cmpl_cback) {
  do_in_main_thread(FROM_HERE,
                    base::Bind(bta_dm_ble_get_energy_info, p_cmpl_cback));
}

/** This function is to set maximum LE data packet size */
void BTA_DmBleRequestMaxTxDataLength(const RawAddress& remote_device) {
  do_in_main_thread(FROM_HERE,
                    base::Bind(bta_dm_ble_set_data_length, remote_device));
}

/*******************************************************************************
 *
 * Function         BTA_DmSetEncryption
 *
 * Description      This function is called to ensure that connection is
 *                  encrypted.  Should be called only on an open connection.
 *                  Typically only needed for connections that first want to
 *                  bring up unencrypted links, then later encrypt them.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *                  transport     - transport of the link to be encruypted
 *                  p_callback    - Pointer to callback function to indicat the
 *                                  link encryption status
 *                  sec_act       - This is the security action to indicate
 *                                  what kind of BLE security level is required
 *                                  for the BLE link if BLE is supported.
 *                                  Note: This parameter is ignored for the
 *                                        BR/EDR or if BLE is not supported.
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmSetEncryption(const RawAddress& bd_addr, tBT_TRANSPORT transport,
                         tBTA_DM_ENCRYPT_CBACK* p_callback,
                         tBTM_BLE_SEC_ACT sec_act) {
  APPL_TRACE_API("%s", __func__);
  do_in_main_thread(FROM_HERE, base::Bind(bta_dm_set_encryption, bd_addr,
                                          transport, p_callback, sec_act));
}

/*******************************************************************************
 *
 * Function         BTA_DmCloseACL
 *
 * Description      This function force to close an ACL connection and remove
 *                  the device from the security database list of known devices.
 *
 * Parameters:      bd_addr       - Address of the peer device
 *                  remove_dev    - remove device or not after link down
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_DmCloseACL(const RawAddress& bd_addr, bool remove_dev,
                    tBT_TRANSPORT transport) {
  do_in_main_thread(
      FROM_HERE, base::Bind(bta_dm_close_acl, bd_addr, remove_dev, transport));
}

/*******************************************************************************
 *
 * Function         BTA_DmBleObserve
 *
 * Description      This procedure keep the device listening for advertising
 *                  events from a broadcast device.
 *
 * Parameters       start: start or stop observe.
 *
 * Returns          void

 *
 * Returns          void.
 *
 ******************************************************************************/
extern void BTA_DmBleObserve(bool start, uint8_t duration,
                             tBTA_DM_SEARCH_CBACK* p_results_cb) {
  APPL_TRACE_API("%s:start = %d ", __func__, start);
  do_in_main_thread(
      FROM_HERE, base::Bind(bta_dm_ble_observe, start, duration, p_results_cb));
}

/*******************************************************************************
 *
 * Function         BTA_VendorInit
 *
 * Description      This function initializes vendor specific
 *
 * Returns          void
 *
 ******************************************************************************/
void BTA_VendorInit(void) { APPL_TRACE_API("BTA_VendorInit"); }
