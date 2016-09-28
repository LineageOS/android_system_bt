/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
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
 *  This file contains the Bluetooth Manager (BTM) API function external
 *  definitions.
 *
 ******************************************************************************/
#ifndef BTM_BLE_API_H
#define BTM_BLE_API_H

#include "btm_api.h"
#include "bt_common.h"
#include "osi/include/alarm.h"
#include <hardware/bt_common_types.h>
#include "btm_ble_api_types.h"

tBTM_BLE_SCAN_SETUP_CBACK bta_ble_scan_setup_cb;

/*****************************************************************************
**  EXTERNAL FUNCTION DECLARATIONS
*****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif
/*******************************************************************************
**
** Function         BTM_SecAddBleDevice
**
** Description      Add/modify device.  This function will be normally called
**                  during host startup to restore all required information
**                  for a LE device stored in the NVRAM.
**
** Parameters:      bd_addr          - BD address of the peer
**                  bd_name          - Name of the peer device.  NULL if unknown.
**                  dev_type         - Remote device's device type.
**                  addr_type        - LE device address type.
**
** Returns          TRUE if added OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SecAddBleDevice (const BD_ADDR bd_addr, BD_NAME bd_name,
                                           tBT_DEVICE_TYPE dev_type, tBLE_ADDR_TYPE addr_type);

/*******************************************************************************
**
** Function         BTM_SecAddBleKey
**
** Description      Add/modify LE device information.  This function will be
**                  normally called during host startup to restore all required
**                  information stored in the NVRAM.
**
** Parameters:      bd_addr          - BD address of the peer
**                  p_le_key         - LE key values.
**                  key_type         - LE SMP key type.
*
** Returns          TRUE if added OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SecAddBleKey (BD_ADDR bd_addr, tBTM_LE_KEY_VALUE *p_le_key,
                                 tBTM_LE_KEY_TYPE key_type);

/*******************************************************************************
**
** Function         BTM_BleSetAdvParams
**
** Description      This function is called to set advertising parameters.
**
** Parameters:       None.
**
** Returns          void
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleSetAdvParams(UINT16 adv_int_min, UINT16 adv_int_max,
                                       tBLE_BD_ADDR *p_dir_bda, tBTM_BLE_ADV_CHNL_MAP chnl_map);

/*******************************************************************************
**
** Function         BTM_BleWriteAdvData
**
** Description      This function is called to write advertising data.
**
** Parameters:       None.
**
** Returns          void
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleWriteAdvData(tBTM_BLE_AD_MASK  data_mask,
                                       tBTM_BLE_ADV_DATA *p_data);

/*******************************************************************************
**
** Function         BTM_BleSetAdvParams
**
** Description      This function is called to set advertising parameters.
**
** Parameters       adv_int_min: minimum advertising interval
**                  adv_int_max: maximum advertising interval
**                  p_dir_bda: connectable direct initiator's LE device address
**                  chnl_map: advertising channel map.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleReadAdvParams (UINT16 *adv_int_min, UINT16 *adv_int_max,
                                  tBLE_BD_ADDR *p_dir_bda, tBTM_BLE_ADV_CHNL_MAP *p_chnl_map);

/*******************************************************************************
**
** Function         BTM_BleObtainVendorCapabilities
**
** Description      This function is called to obatin vendor capabilties
**
** Parameters       p_cmn_vsc_cb - Returns the vednor capabilities
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleObtainVendorCapabilities(tBTM_BLE_VSC_CB *p_cmn_vsc_cb);

/*******************************************************************************
**
** Function         BTM_BleSetScanParams
**
** Description      This function is called to set Scan parameters.
**
** Parameters       client_if - Client IF value
**                  scan_interval - Scan interval
**                  scan_window - Scan window
**                  scan_type - Scan type
**                  scan_setup_status_cback - Scan setup status callback
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleSetScanParams(tGATT_IF client_if, UINT32 scan_interval,
                                 UINT32 scan_window, tBLE_SCAN_MODE scan_type,
                                 tBLE_SCAN_PARAM_SETUP_CBACK scan_setup_status_cback);

/*******************************************************************************
**
** Function         BTM_BleGetVendorCapabilities
**
** Description      This function reads local LE features
**
** Parameters       p_cmn_vsc_cb : Locala LE capability structure
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleGetVendorCapabilities(tBTM_BLE_VSC_CB *p_cmn_vsc_cb);
/*******************************************************************************
**
** Function         BTM_BleSetStorageConfig
**
** Description      This function is called to setup storage configuration and setup callbacks.
**
** Parameters       UINT8 batch_scan_full_max -Batch scan full maximum
                    UINT8 batch_scan_trunc_max - Batch scan truncated value maximum
                    UINT8 batch_scan_notify_threshold - Threshold value
                    tBTM_BLE_SCAN_SETUP_CBACK *p_setup_cback - Setup callback
                    tBTM_BLE_SCAN_THRESHOLD_CBACK *p_thres_cback -Threshold callback
                    void *p_ref - Reference value
**
** Returns          tBTM_STATUS
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleSetStorageConfig(UINT8 batch_scan_full_max,
                                        UINT8 batch_scan_trunc_max,
                                        UINT8 batch_scan_notify_threshold,
                                        tBTM_BLE_SCAN_SETUP_CBACK *p_setup_cback,
                                        tBTM_BLE_SCAN_THRESHOLD_CBACK *p_thres_cback,
                                        tBTM_BLE_SCAN_REP_CBACK* p_cback,
                                        tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleEnableBatchScan
**
** Description      This function is called to enable batch scan
**
** Parameters       tBTM_BLE_BATCH_SCAN_MODE scan_mode - Batch scan mode
                    UINT32 scan_interval -Scan interval
                    UINT32 scan_window - Scan window value
                    tBLE_ADDR_TYPE addr_type - Address type
                    tBTM_BLE_DISCARD_RULE discard_rule - Data discard rules
**
** Returns          tBTM_STATUS
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleEnableBatchScan(tBTM_BLE_BATCH_SCAN_MODE scan_mode,
                                        UINT32 scan_interval, UINT32 scan_window,
                                        tBTM_BLE_DISCARD_RULE discard_rule,
                                        tBLE_ADDR_TYPE addr_type,
                                        tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleDisableBatchScan
**
** Description      This function is called to disable batch scanning
**
** Parameters       void
**
** Returns          void
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleDisableBatchScan(tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleReadScanReports
**
** Description      This function is called to read batch scan reports
**
** Parameters       tBLE_SCAN_MODE scan_mode - Scan mode report to be read out
                    tBTM_BLE_SCAN_REP_CBACK* p_cback - Reports callback
**
** Returns          tBTM_STATUS
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleReadScanReports(tBLE_SCAN_MODE scan_mode,
                                                  tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleTrackAdvertiser
**
** Description      This function is called to read batch scan reports
**
** Parameters       p_track_cback - Tracking callback
**                  ref_value - Reference value
**
** Returns          tBTM_STATUS
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleTrackAdvertiser(tBTM_BLE_TRACK_ADV_CBACK *p_track_cback,
                                                  tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleWriteScanRsp
**
** Description      This function is called to write LE scan response.
**
** Parameters:      p_scan_rsp: scan response.
**
** Returns          status
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleWriteScanRsp(tBTM_BLE_AD_MASK data_mask,
                                       tBTM_BLE_ADV_DATA *p_data);

/*******************************************************************************
**
** Function         BTM_BleObserve
**
** Description      This procedure keep the device listening for advertising
**                  events from a broadcast device.
**
** Parameters       start: start or stop observe.
**
** Returns          void
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleObserve(BOOLEAN start, UINT8 duration,
                                  tBTM_INQ_RESULTS_CB *p_results_cb, tBTM_CMPL_CB *p_cmpl_cb);


/*******************************************************************************
**
** Function         BTM_GetDeviceIDRoot
**
** Description      This function is called to read the local device identity
**                  root.
**
** Returns          void
**                  the local device ER is copied into er
**
*******************************************************************************/
extern void BTM_GetDeviceIDRoot (BT_OCTET16 ir);

/*******************************************************************************
**
** Function         BTM_GetDeviceEncRoot
**
** Description      This function is called to read the local device encryption
**                  root.
**
** Returns          void
**                  the local device ER is copied into er
**
*******************************************************************************/
extern void BTM_GetDeviceEncRoot (BT_OCTET16 er);

/*******************************************************************************
**
** Function         BTM_GetDeviceDHK
**
** Description      This function is called to read the local device DHK.
**
** Returns          void
**                  the local device DHK is copied into dhk
**
*******************************************************************************/
extern void BTM_GetDeviceDHK (BT_OCTET16 dhk);

/*******************************************************************************
**
** Function         BTM_SecurityGrant
**
** Description      This function is called to grant security process.
**
** Parameters       bd_addr - peer device bd address.
**                  res     - result of the operation BTM_SUCCESS if success.
**                            Otherwise, BTM_REPEATED_ATTEMPTS is too many attempts.
**
** Returns          None
**
*******************************************************************************/
extern void BTM_SecurityGrant(BD_ADDR bd_addr, UINT8 res);

/*******************************************************************************
**
** Function         BTM_BlePasskeyReply
**
** Description      This function is called after Security Manager submitted
**                  passkey request to the application.
**
** Parameters:      bd_addr      - Address of the device for which passkey was requested
**                  res          - result of the operation SMP_SUCCESS if success
**                  passkey - numeric value in the range of
**                  BTM_MIN_PASSKEY_VAL(0) - BTM_MAX_PASSKEY_VAL(999999(0xF423F)).
**
*******************************************************************************/
extern void BTM_BlePasskeyReply (BD_ADDR bd_addr, UINT8 res, UINT32 passkey);

/*******************************************************************************
**
** Function         BTM_BleConfirmReply
**
** Description      This function is called after Security Manager submitted
**                  numeric comparison request to the application.
**
** Parameters:      bd_addr      - Address of the device with which numeric
**                                 comparison was requested
**                  res          - comparison result BTM_SUCCESS if success
**
*******************************************************************************/
extern void BTM_BleConfirmReply (BD_ADDR bd_addr, UINT8 res);

/*******************************************************************************
**
** Function         BTM_LeOobDataReply
**
** Description      This function is called to provide the OOB data for
**                  SMP in response to BTM_LE_OOB_REQ_EVT
**
** Parameters:      bd_addr     - Address of the peer device
**                  res         - result of the operation SMP_SUCCESS if success
**                  p_data      - simple pairing Randomizer  C.
**
*******************************************************************************/
extern void BTM_BleOobDataReply(BD_ADDR bd_addr, UINT8 res, UINT8 len, UINT8 *p_data);

/*******************************************************************************
**
** Function         BTM_BleSecureConnectionOobDataReply
**
** Description      This function is called to provide the OOB data for
**                  SMP in response to BTM_LE_OOB_REQ_EVT when secure connection
**                  data is available
**
** Parameters:      bd_addr     - Address of the peer device
**                  p_c         - pointer to Confirmation
**                  p_r         - pointer to Randomizer.
**
*******************************************************************************/
extern void BTM_BleSecureConnectionOobDataReply(BD_ADDR bd_addr,
                                                uint8_t *p_c, uint8_t *p_r);


/*******************************************************************************
**
** Function         BTM_BleDataSignature
**
** Description      This function is called to sign the data using AES128 CMAC
**                  algorith.
**
** Parameter        bd_addr: target device the data to be signed for.
**                  p_text: singing data
**                  len: length of the signing data
**                  signature: output parameter where data signature is going to
**                             be stored.
**
** Returns          TRUE if signing sucessul, otherwise FALSE.
**
*******************************************************************************/
extern BOOLEAN BTM_BleDataSignature (BD_ADDR bd_addr, UINT8 *p_text, UINT16 len,
                                     BLE_SIGNATURE signature);

/*******************************************************************************
**
** Function         BTM_BleVerifySignature
**
** Description      This function is called to verify the data signature
**
** Parameter        bd_addr: target device the data to be signed for.
**                  p_orig:  original data before signature.
**                  len: length of the signing data
**                  counter: counter used when doing data signing
**                  p_comp: signature to be compared against.

** Returns          TRUE if signature verified correctly; otherwise FALSE.
**
*******************************************************************************/
extern BOOLEAN BTM_BleVerifySignature (BD_ADDR bd_addr, UINT8 *p_orig,
                                       UINT16 len, UINT32 counter,
                                       UINT8 *p_comp);

/*******************************************************************************
**
** Function         BTM_ReadConnectionAddr
**
** Description      This function is called to set the local device random address
**                  .
**
** Returns          void
**
*******************************************************************************/
extern void BTM_ReadConnectionAddr (BD_ADDR remote_bda, BD_ADDR local_conn_addr,
                                            tBLE_ADDR_TYPE *p_addr_type);

/*******************************************************************************
 *
 * Function         BTM_IsBleConnection
 *
 * Description      This function is called to check if the connection handle
 *                  for an LE link
 *
 * Returns          true if connection is LE link, otherwise false.
 *
 ******************************************************************************/
extern bool BTM_IsBleConnection(uint16_t conn_handle);

/*******************************************************************************
**
** Function         BTM_ReadRemoteConnectionAddr
**
** Description      This function is read the remote device address currently used
**                  .
**
** Returns          void
**
*******************************************************************************/
extern BOOLEAN BTM_ReadRemoteConnectionAddr(BD_ADDR pseudo_addr,
                                                    BD_ADDR conn_addr,
                                                    tBLE_ADDR_TYPE *p_addr_type);

/*******************************************************************************
**
** Function         BTM_BleLoadLocalKeys
**
** Description      Local local identity key, encryption root or sign counter.
**
** Parameters:      key_type: type of key, can be BTM_BLE_KEY_TYPE_ID, BTM_BLE_KEY_TYPE_ER
**                            or BTM_BLE_KEY_TYPE_COUNTER.
**                  p_key: pointer to the key.
*
** Returns          non2.
**
*******************************************************************************/
extern void BTM_BleLoadLocalKeys(UINT8 key_type, tBTM_BLE_LOCAL_KEYS *p_key);


/*******************************************************************************
**
** Function         BTM_BleSetBgConnType
**
** Description      This function is called to set BLE background connection
**                  procedure type. It can be auto connection, or selective connection.
**
** Parameters       conn_type: it can be auto connection, or selective connection.
**                  p_select_cback: callback function when selective connection procedure
**                              is being used.
**
** Returns          void
**
*******************************************************************************/
extern BOOLEAN BTM_BleSetBgConnType(tBTM_BLE_CONN_TYPE   conn_type,
                                    tBTM_BLE_SEL_CBACK   *p_select_cback);

/*******************************************************************************
**
** Function         BTM_BleUpdateBgConnDev
**
** Description      This function is called to add or remove a device into/from
**                  background connection procedure. The background connection
*                   procedure is decided by the background connection type, it can be
*                   auto connection, or selective connection.
**
** Parameters       add_remove: TRUE to add; FALSE to remove.
**                  remote_bda: device address to add/remove.
**
** Returns          void
**
*******************************************************************************/
extern BOOLEAN BTM_BleUpdateBgConnDev(BOOLEAN add_remove, BD_ADDR   remote_bda);

/*******************************************************************************
**
** Function         BTM_BleClearBgConnDev
**
** Description      This function is called to clear the whitelist,
**                  end any pending whitelist connections,
*                   and reset the local bg device list.
**
** Parameters       void
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleClearBgConnDev(void);

/********************************************************
**
** Function         BTM_BleSetPrefConnParams
**
** Description      Set a peripheral's preferred connection parameters. When
**                  any of the value does not want to be updated while others
**                  do, use BTM_BLE_CONN_PARAM_UNDEF for the ones want to
**                  leave untouched.
**
** Parameters:      bd_addr          - BD address of the peripheral
**                  min_conn_int     - minimum preferred connection interval
**                  max_conn_int     - maximum preferred connection interval
**                  slave_latency    - preferred slave latency
**                  supervision_tout - preferred supervision timeout
**
** Returns          void
**
*******************************************************************************/
extern  void BTM_BleSetPrefConnParams (BD_ADDR bd_addr,
                                               UINT16 min_conn_int,  UINT16 max_conn_int,
                                               UINT16 slave_latency, UINT16 supervision_tout);

/******************************************************************************
**
** Function         BTM_BleSetConnScanParams
**
** Description      Set scan parameters used in BLE connection request
**
** Parameters:      scan_interval    - scan interval
**                  scan_window      - scan window
**
** Returns          void
**
*******************************************************************************/
extern  void BTM_BleSetConnScanParams (UINT32 scan_interval, UINT32 scan_window);

/******************************************************************************
**
** Function         BTM_BleReadControllerFeatures
**
** Description      Reads BLE specific controller features
**
** Parameters:      tBTM_BLE_CTRL_FEATURES_CBACK : Callback to notify when features are read
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleReadControllerFeatures(tBTM_BLE_CTRL_FEATURES_CBACK  *p_vsc_cback);

/*******************************************************************************
**
** Function         BTM_CheckAdvData
**
** Description      This function is called to get ADV data for a specific type.
**
** Parameters       p_adv - pointer of ADV data
**                  type   - finding ADV data type
**                  p_length - return the length of ADV data not including type
**
** Returns          pointer of ADV data
**
*******************************************************************************/
extern  UINT8 *BTM_CheckAdvData( UINT8 *p_adv, UINT8 type, UINT8 *p_length);

/*******************************************************************************
**
** Function         BTM__BLEReadDiscoverability
**
** Description      This function is called to read the current LE discoverability
**                  mode of the device.
**
** Returns          BTM_BLE_NON_DISCOVERABLE ,BTM_BLE_LIMITED_DISCOVERABLE or
**                     BTM_BLE_GENRAL_DISCOVERABLE
**
*******************************************************************************/
UINT16 BTM_BleReadDiscoverability();

/*******************************************************************************
**
** Function         BTM__BLEReadConnectability
**
** Description      This function is called to read the current LE connectibility
**                  mode of the device.
**
** Returns          BTM_BLE_NON_CONNECTABLE or BTM_BLE_CONNECTABLE
**
*******************************************************************************/
extern UINT16 BTM_BleReadConnectability ();

/*******************************************************************************
**
** Function         BTM_ReadDevInfo
**
** Description      This function is called to read the device/address type
**                  of BD address.
**
** Parameter        remote_bda: remote device address
**                  p_dev_type: output parameter to read the device type.
**                  p_addr_type: output parameter to read the address type.
**
*******************************************************************************/
extern void BTM_ReadDevInfo (BD_ADDR remote_bda, tBT_DEVICE_TYPE *p_dev_type,
                                     tBLE_ADDR_TYPE *p_addr_type);


/*******************************************************************************
**
** Function         BTM_ReadConnectedTransportAddress
**
** Description      This function is called to read the paired device/address type of other device paired
**                  corresponding to the BD_address
**
** Parameter        remote_bda: remote device address, carry out the transport address
**                  transport: active transport
**
** Return           TRUE if an active link is identified; FALSE otherwise
**
*******************************************************************************/
extern BOOLEAN BTM_ReadConnectedTransportAddress(BD_ADDR remote_bda,
                                                 tBT_TRANSPORT transport);

/*******************************************************************************
**
** Function         BTM_BleBroadcast
**
** Description      This function is to start or stop broadcasting.
**
** Parameters       start: start or stop broadcasting.
**
** Returns          status.
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleBroadcast(BOOLEAN start);

/*******************************************************************************
**
** Function         BTM_BleConfigPrivacy
**
** Description      This function is called to enable or disable the privacy in
**                  the local device.
**
** Parameters       enable: TRUE to enable it; FALSE to disable it.
**
** Returns          BOOLEAN privacy mode set success; otherwise failed.
**
*******************************************************************************/
extern BOOLEAN BTM_BleConfigPrivacy(BOOLEAN enable);

/*******************************************************************************
**
** Function         BTM_BleLocalPrivacyEnabled
**
** Description        Checks if local device supports private address
**
** Returns          Return TRUE if local privacy is enabled else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_BleLocalPrivacyEnabled(void);

/*******************************************************************************
**
** Function         BTM_BleEnableMixedPrivacyMode
**
** Description      This function is called to enabled Mixed mode if privacy 1.2
**                  is applicable in controller.
**
** Parameters       mixed_on:  mixed mode to be used or not.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleEnableMixedPrivacyMode(BOOLEAN mixed_on);

/*******************************************************************************
**
** Function          BTM_BleMaxMultiAdvInstanceCount
**
** Description        Returns max number of multi adv instances  supported by controller
**
** Returns          Max multi adv instance count
**
*******************************************************************************/
extern UINT8  BTM_BleMaxMultiAdvInstanceCount();

/*******************************************************************************
**
** Function         BTM_BleSetConnectableMode
**
** Description      This function is called to set BLE connectable mode for a
**                  peripheral device.
**
** Parameters       connectable_mode:  directed connectable mode, or non-directed.It can
**                              be BTM_BLE_CONNECT_EVT, BTM_BLE_CONNECT_DIR_EVT or
**                              BTM_BLE_CONNECT_LO_DUTY_DIR_EVT
**
** Returns          BTM_ILLEGAL_VALUE if controller does not support BLE.
**                  BTM_SUCCESS is status set successfully; otherwise failure.
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleSetConnectableMode(tBTM_BLE_CONN_MODE connectable_mode);

/*******************************************************************************
**
** Function         BTM_BleTurnOnPrivacyOnRemote
**
** Description      This function is called to enable or disable the privacy on the
**                  remote device.
**
** Parameters       bd_addr: remote device address.
**                  privacy_on: TRUE to enable it; FALSE to disable it.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_BleTurnOnPrivacyOnRemote(BD_ADDR bd_addr,
                                                 BOOLEAN privacy_on);

/*******************************************************************************
**
** Function         BTM_BleUpdateAdvWhitelist
**
** Description      Add or remove device from advertising white list
**
** Returns          void
**
*******************************************************************************/
extern BOOLEAN BTM_BleUpdateAdvWhitelist(BOOLEAN add_remove, BD_ADDR emote_bda);

/*******************************************************************************
**
** Function         BTM_BleUpdateAdvFilterPolicy
**
** Description      This function update the filter policy of advertiser.
**
** Parameter        adv_policy: advertising filter policy
**
** Return           void
*******************************************************************************/
extern void BTM_BleUpdateAdvFilterPolicy(tBTM_BLE_AFP adv_policy);

/*******************************************************************************
**
** Function         BTM_BleReceiverTest
**
** Description      This function is called to start the LE Receiver test
**
** Parameter       rx_freq - Frequency Range
**               p_cmd_cmpl_cback - Command Complete callback
**
*******************************************************************************/
void BTM_BleReceiverTest(UINT8 rx_freq, tBTM_CMPL_CB *p_cmd_cmpl_cback);


/*******************************************************************************
**
** Function         BTM_BleTransmitterTest
**
** Description      This function is called to start the LE Transmitter test
**
** Parameter       tx_freq - Frequency Range
**                       test_data_len - Length in bytes of payload data in each packet
**                       packet_payload - Pattern to use in the payload
**                       p_cmd_cmpl_cback - Command Complete callback
**
*******************************************************************************/
void BTM_BleTransmitterTest(UINT8 tx_freq, UINT8 test_data_len,
                                 UINT8 packet_payload, tBTM_CMPL_CB *p_cmd_cmpl_cback);

/*******************************************************************************
**
** Function         BTM_BleTestEnd
**
** Description      This function is called to stop the in-progress TX or RX test
**
** Parameter       p_cmd_cmpl_cback - Command complete callback
**
*******************************************************************************/
void BTM_BleTestEnd(tBTM_CMPL_CB *p_cmd_cmpl_cback);

/*******************************************************************************
**
** Function         BTM_UseLeLink
**
** Description      This function is to select the underneath physical link to use.
**
** Returns          TRUE to use LE, FALSE use BR/EDR.
**
*******************************************************************************/
extern BOOLEAN BTM_UseLeLink (BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_BleStackEnable
**
** Description      Enable/Disable BLE functionality on stack regarless controller
**                  capability.
**
** Parameters:      enable: TRUE to enable, FALSE to disable.
**
** Returns          TRUE if added OK, else FALSE
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleStackEnable (BOOLEAN enable);

/*******************************************************************************
**
** Function         BTM_GetLeSecurityState
**
** Description      This function is called to get security mode 1 flags and
**                  encryption key size for LE peer.
**
** Returns          BOOLEAN TRUE if LE device is found, FALSE otherwise.
**
*******************************************************************************/
extern BOOLEAN BTM_GetLeSecurityState (BD_ADDR bd_addr,
                                               UINT8 *p_le_dev_sec_flags,
                                               UINT8 *p_le_key_size);

/*******************************************************************************
**
** Function         BTM_BleSecurityProcedureIsRunning
**
** Description      This function indicates if LE security procedure is
**                  currently running with the peer.
**
** Returns          BOOLEAN TRUE if security procedure is running, FALSE otherwise.
**
*******************************************************************************/
extern BOOLEAN BTM_BleSecurityProcedureIsRunning (BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_BleGetSupportedKeySize
**
** Description      This function gets the maximum encryption key size in bytes
**                  the local device can suport.
**                  record.
**
** Returns          the key size or 0 if the size can't be retrieved.
**
*******************************************************************************/
extern UINT8 BTM_BleGetSupportedKeySize (BD_ADDR bd_addr);

/*******************************************************************************/
/*                          Multi ADV API                                      */
/*******************************************************************************
**
** Function         BTM_BleEnableAdvInstance
**
** Description      This function enable a Multi-ADV instance with the specified
**                  adv parameters
**
** Parameters       p_params: pointer to the adv parameter structure, set as default
**                            adv parameter when the instance is enabled.
**                  p_cback: callback function for the adv instance.
**                  p_ref:  reference data attach to the adv instance to be enabled.
**
** Returns          status
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleEnableAdvInstance (tBTM_BLE_ADV_PARAMS *p_params,
                                      tBTM_BLE_MULTI_ADV_CBACK *p_cback,
                                      void *p_ref);

/*******************************************************************************
**
** Function         BTM_BleUpdateAdvInstParam
**
** Description      This function update a Multi-ADV instance with the specififed
**                  adv parameters.
**
** Parameters       inst_id: adv instance ID
**                  p_params: pointer to the adv parameter structure.
**
** Returns          status
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleUpdateAdvInstParam (UINT8 inst_id, tBTM_BLE_ADV_PARAMS *p_params);

/*******************************************************************************
**
** Function         BTM_BleCfgAdvInstData
**
** Description      This function configure a Multi-ADV instance with the specified
**                  adv data or scan response data.
**
** Parameters       inst_id: adv instance ID
**                  is_scan_rsp: is this scacn response, if no set as adv data.
**                  data_mask: adv data mask.
**                  p_data: pointer to the adv data structure.
**
** Returns          status
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleCfgAdvInstData (UINT8 inst_id, BOOLEAN is_scan_rsp,
                                    tBTM_BLE_AD_MASK data_mask,
                                    tBTM_BLE_ADV_DATA *p_data);

/*******************************************************************************
**
** Function         BTM_BleDisableAdvInstance
**
** Description      This function disable a Multi-ADV instance.
**
** Parameters       inst_id: adv instance ID
**
** Returns          status
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleDisableAdvInstance (UINT8 inst_id);

/*******************************************************************************
**
** Function         BTM_BleAdvFilterParamSetup
**
** Description      This function is called to setup the adv data payload filter
**                  condition.
**
** Parameters       p_target: enabble the filter condition on a target device; if NULL
**                            enable the generic scan condition.
**                  enable: enable or disable the filter condition
**
** Returns          void
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleAdvFilterParamSetup(int action,
                                tBTM_BLE_PF_FILT_INDEX filt_index,
                                tBTM_BLE_PF_FILT_PARAMS *p_filt_params,
                                tBLE_BD_ADDR *p_target, tBTM_BLE_PF_PARAM_CBACK *p_cmpl_cback,
                                tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleCfgFilterCondition
**
** Description      This function is called to configure the adv data payload filter
**                  condition.
**
** Parameters       action: to read/write/clear
**                  cond_type: filter condition type.
**                  p_cond: filter condition paramter
**
** Returns          tBTM_STATUS
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleCfgFilterCondition(tBTM_BLE_SCAN_COND_OP action,
                                      tBTM_BLE_PF_COND_TYPE cond_type,
                                      tBTM_BLE_PF_FILT_INDEX filt_index,
                                      tBTM_BLE_PF_COND_PARAM *p_cond,
                                      tBTM_BLE_PF_CFG_CBACK *p_cmpl_cback,
                                      tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleEnableDisableFilterFeature
**
** Description      This function is called to enable or disable the APCF feature
**
** Parameters       enable - TRUE - enables the APCF, FALSE - disables the APCF
**                       ref_value - Ref value
**
** Returns          tBTM_STATUS
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleEnableDisableFilterFeature(UINT8 enable,
                                               tBTM_BLE_PF_STATUS_CBACK *p_stat_cback,
                                               tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
**
** Function         BTM_BleGetEnergyInfo
**
** Description      This function obtains the energy info
**
** Parameters       p_ener_cback - Callback pointer
**
** Returns          status
**
*******************************************************************************/
extern tBTM_STATUS BTM_BleGetEnergyInfo(tBTM_BLE_ENERGY_INFO_CBACK *p_ener_cback);

/*******************************************************************************
**
** Function         BTM_SetBleDataLength
**
** Description      This function is called to set maximum BLE transmission packet size
**
** Returns          BTM_SUCCESS if success; otherwise failed.
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetBleDataLength(BD_ADDR bd_addr, UINT16 tx_pdu_length);

#ifdef __cplusplus
}
#endif

#endif
