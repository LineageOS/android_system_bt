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

#pragma once

#include <cstdint>
#include "stack/btm/neighbor_inquiry.h"
#include "stack/include/acl_client_callbacks.h"
#include "stack/include/btm_api_types.h"
#include "stack/include/btm_ble_api_types.h"
#include "stack/include/btm_status.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/hcidefs.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

struct btm_client_interface_s {
  struct {
    tBTM_STATUS (*BTM_PmRegister)(uint8_t mask, uint8_t* p_pm_id,
                                  tBTM_PM_STATUS_CBACK* p_cback);
    uint16_t (*BTM_GetHCIConnHandle)(const RawAddress& bd_addr,
                                     tBT_TRANSPORT transport);
    void (*BTM_VendorSpecificCommand)(uint16_t opcode, uint8_t param_len,
                                      uint8_t* p_param_buf,
                                      tBTM_VSC_CMPL_CB* p_cb);
    void (*ACL_RegisterClient)(struct acl_client_callback_s* callbacks);
    void (*ACL_UnregisterClient)(struct acl_client_callback_s* callbacks);
    void (*btm_init)();
    void (*btm_free)();
    void (*btm_ble_init)();
    void (*btm_ble_free)();
  } lifecycle;

  struct {
    // Server channel number
    bool (*BTM_FreeSCN)(uint8_t scn);
  } scn;

  // Neighbor
  struct {
    void (*BTM_CancelInquiry)();
    tBTM_INQ_INFO* (*BTM_InqDbNext)(tBTM_INQ_INFO* p_cur);
    tBTM_STATUS (*BTM_ClearInqDb)(const RawAddress* p_bda);
    tBTM_STATUS (*BTM_SetDiscoverability)(uint16_t inq_mode);
    tBTM_STATUS (*BTM_SetConnectability)(uint16_t page_mode);
  } neighbor;

  // Acl peer and lifecycle
  struct {
    bool (*BTM_IsAclConnectionUp)(const RawAddress& bd_addr,
                                  tBT_TRANSPORT transport);
    bool (*BTM_ReadConnectedTransportAddress)(RawAddress* bd_addr,
                                              tBT_TRANSPORT transport);
    tBTM_STATUS (*BTM_CancelRemoteDeviceName)(void);
    tBTM_STATUS (*BTM_ReadRemoteDeviceName)(const RawAddress& bd_addr,
                                            tBTM_CMPL_CB* p_cb,
                                            tBT_TRANSPORT transport);
    tBTM_STATUS (*BTM_SetEncryption)(const RawAddress& bd_addr,
                                     tBT_TRANSPORT transport,
                                     tBTM_SEC_CALLBACK* p_callback,
                                     void* p_ref_data,
                                     tBTM_BLE_SEC_ACT sec_act);
    uint8_t* (*BTM_ReadRemoteFeatures)(const RawAddress&);
    void (*BTM_ReadDevInfo)(const RawAddress& bd_addr,
                            tBT_DEVICE_TYPE* p_dev_type,
                            tBLE_ADDR_TYPE* p_addr_type);
    uint16_t (*BTM_GetMaxPacketSize)(const RawAddress& bd_addr);
  } peer;

  struct {
    tBTM_STATUS (*BTM_GetRole)(const RawAddress& remote_bd_addr,
                               uint8_t* p_role);
    tBTM_STATUS (*BTM_SetPowerMode)(uint8_t pm_id, const RawAddress& bd_addr,
                                    const tBTM_PM_PWR_MD* p_mode);
    tBTM_STATUS (*BTM_SetSsrParams)(const RawAddress& bd_addr, uint16_t max_lat,
                                    uint16_t min_rmt_to, uint16_t min_loc_to);
    tBTM_STATUS (*BTM_SwitchRoleToCentral)(const RawAddress& remote_bd_addr);
    void (*BTM_block_role_switch_for)(const RawAddress& peer_addr);
    void (*BTM_block_sniff_mode_for)(const RawAddress& peer_addr);
    void (*BTM_default_unblock_role_switch)();
    void (*BTM_unblock_role_switch_for)(const RawAddress& peer_addr);
    void (*BTM_unblock_sniff_mode_for)(const RawAddress& peer_addr);
    void (*BTM_WritePageTimeout)(uint16_t timeout);
  } link_policy;

  struct {
    tBTM_STATUS (*BTM_GetLinkSuperTout)(const RawAddress& bd_addr,
                                        uint16_t* p_timeout);
    void (*BTM_SetDefaultLinkSuperTout)(uint16_t timeout);
    tBTM_STATUS (*BTM_ReadRSSI)(const RawAddress& bd_addr, tBTM_CMPL_CB* p_cb);
  } link_controller;

  struct {
    bool (*BTM_SecAddDevice)(const RawAddress& bd_addr, DEV_CLASS dev_class,
                             BD_NAME bd_name, uint8_t* features,
                             LinkKey* link_key, uint8_t key_type,
                             uint8_t pin_length);
    bool (*BTM_SecAddRmtNameNotifyCallback)(tBTM_RMT_NAME_CALLBACK* p_callback);
    bool (*BTM_SecDeleteDevice)(const RawAddress& bd_addr);
    bool (*BTM_SecDeleteRmtNameNotifyCallbac)(
        tBTM_RMT_NAME_CALLBACK* p_callback);
    bool (*BTM_SecRegister)(const tBTM_APPL_INFO* p_cb_info);
    char* (*BTM_SecReadDevName)(const RawAddress& bd_addr);
    tBTM_STATUS (*BTM_SecBond)(const RawAddress& bd_addr,
                               tBLE_ADDR_TYPE addr_type,
                               tBT_TRANSPORT transport, int device_type,
                               uint8_t pin_len, uint8_t* p_pin);
    tBTM_STATUS (*BTM_SecBondCancel)(const RawAddress& bd_addr);
    void (*BTM_SecAddBleKey)(const RawAddress& bd_addr,
                             tBTM_LE_KEY_VALUE* p_le_key,
                             tBTM_LE_KEY_TYPE key_type);
    void (*BTM_SecAddBleDevice)(const RawAddress& bd_addr,
                                tBT_DEVICE_TYPE dev_type,
                                tBLE_ADDR_TYPE addr_type);
    void (*BTM_SecClearSecurityFlags)(const RawAddress& bd_addr);
    uint8_t (*BTM_SecClrServiceByPsm)(uint16_t psm);
    void (*BTM_RemoteOobDataReply)(tBTM_STATUS res, const RawAddress& bd_addr,
                                   const Octet16& c, const Octet16& r);
    void (*BTM_PINCodeReply)(const RawAddress& bd_addr, uint8_t res,
                             uint8_t pin_len, uint8_t* p_pin);
    void (*BTM_ConfirmReqReply)(tBTM_STATUS res, const RawAddress& bd_addr);
    bool (*BTM_SecDeleteRmtNameNotifyCallback)(
        tBTM_RMT_NAME_CALLBACK* p_callback);

  } security;

  struct {
    tBTM_STATUS (*BTM_BleGetEnergyInfo)(tBTM_BLE_ENERGY_INFO_CBACK* callback);
    tBTM_STATUS (*BTM_BleObserve)(bool start, uint8_t duration,
                                  tBTM_INQ_RESULTS_CB* p_results_cb,
                                  tBTM_CMPL_CB* p_cmpl_cb);
    tBTM_STATUS (*BTM_SetBleDataLength)(const RawAddress& bd_addr,
                                        uint16_t tx_pdu_length);
    void (*BTM_BleConfirmReply)(const RawAddress& bd_addr, uint8_t res);
    void (*BTM_BleLoadLocalKeys)(uint8_t key_type, tBTM_BLE_LOCAL_KEYS* p_key);
    void (*BTM_BlePasskeyReply)(const RawAddress& bd_addr, uint8_t res,
                                uint32_t passkey);
    void (*BTM_BleReadControllerFeatures)(
        tBTM_BLE_CTRL_FEATURES_CBACK* p_vsc_cback);
    void (*BTM_BleSetConnScanParams)(uint32_t scan_interval,
                                     uint32_t scan_window);
    void (*BTM_BleSetPhy)(const RawAddress& bd_addr, uint8_t tx_phys,
                          uint8_t rx_phys, uint16_t phy_options);
    void (*BTM_BleSetPrefConnParams)(const RawAddress& bd_addr,
                                     uint16_t min_conn_int,
                                     uint16_t max_conn_int,
                                     uint16_t peripheral_latency,
                                     uint16_t supervision_tout);
  } ble;

  struct {
    tBTM_STATUS (*BTM_CreateSco)(const RawAddress* bd_addr, bool is_orig,
                                 uint16_t pkt_types, uint16_t* p_sco_inx,
                                 tBTM_SCO_CB* p_conn_cb,
                                 tBTM_SCO_CB* p_disc_cb);
    tBTM_STATUS (*BTM_RegForEScoEvts)(uint16_t sco_inx,
                                      tBTM_ESCO_CBACK* p_esco_cback);
    tBTM_STATUS (*BTM_RemoveSco)(uint16_t sco_inx);
    void (*BTM_WriteVoiceSettings)(uint16_t settings);
    void (*BTM_EScoConnRsp)(uint16_t sco_inx, uint8_t hci_status,
                            enh_esco_params_t* p_parms);
    uint8_t (*BTM_GetNumScoLinks)();
    tBTM_STATUS (*BTM_SetEScoMode)(enh_esco_params_t* p_parms);
  } sco;

  struct {
    tBTM_STATUS (*BTM_ReadLocalDeviceNameFromController)(
        tBTM_CMPL_CB* p_rln_cmpl_cback);
    tBTM_STATUS (*BTM_SetLocalDeviceName)(char* p_name);
    tBTM_STATUS (*BTM_SetDeviceClass)(DEV_CLASS dev_class);
  } local;

  struct {
    tBTM_STATUS (*BTM_WriteEIR)(BT_HDR* p_buff);
    uint8_t (*BTM_GetEirSupportedServices)(uint32_t* p_eir_uuid, uint8_t** p,
                                           uint8_t max_num_uuid16,
                                           uint8_t* p_num_uuid16);
    uint8_t (*BTM_GetEirUuidList)(uint8_t* p_eir, size_t eir_len,
                                  uint8_t uuid_size, uint8_t* p_num_uuid,
                                  uint8_t* p_uuid_list, uint8_t max_num_uuid);
    void (*BTM_RemoveEirService)(uint32_t* p_eir_uuid, uint16_t uuid16);
  } eir;
};

struct btm_client_interface_s& get_btm_client_interface();
