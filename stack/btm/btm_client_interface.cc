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

#include "stack/include/btm_client_interface.h"
#include <cstdint>
#include "main/shim/btm_api.h"
#include "stack/include/acl_api.h"
#include "stack/include/btm_api.h"
#include "stack/include/btm_ble_api.h"
#include "stack/include/btm_client_interface.h"
#include "stack/include/hci_error_code.h"
#include "stack/include/hcidefs.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

struct btm_client_interface_s btm_client_interface = {
    .lifecycle =
        {
            .BTM_GetHCIConnHandle = BTM_GetHCIConnHandle,
            .BTM_PmRegister = BTM_PmRegister,
            .BTM_VendorSpecificCommand = BTM_VendorSpecificCommand,
            .ACL_RegisterClient = ACL_RegisterClient,
            .ACL_UnregisterClient = ACL_UnregisterClient,
            .btm_init = btm_init,
            .btm_free = btm_free,
            .btm_ble_init = btm_ble_init,
            .btm_ble_free = btm_ble_free,
            .BTM_db_reset = BTM_db_reset,
            .BTM_reset_complete = BTM_reset_complete,
        },

    .scn =
        {
            .BTM_AllocateSCN = BTM_AllocateSCN,
            .BTM_TryAllocateSCN = BTM_TryAllocateSCN,
            .BTM_FreeSCN = BTM_FreeSCN,
        },

    .neighbor =
        {
            .BTM_CancelInquiry = BTM_CancelInquiry,
            .BTM_ClearInqDb = BTM_ClearInqDb,
            .BTM_InqDbNext = BTM_InqDbNext,
            .BTM_SetConnectability = BTM_SetConnectability,
            .BTM_SetDiscoverability = BTM_SetDiscoverability,
            .BTM_StartInquiry = BTM_StartInquiry,
            .BTM_IsInquiryActive = BTM_IsInquiryActive,
            .BTM_SetInquiryMode = BTM_SetInquiryMode,
            .BTM_EnableInterlacedInquiryScan = BTM_EnableInterlacedInquiryScan,
            .BTM_EnableInterlacedPageScan = BTM_EnableInterlacedPageScan,
        },

    // Acl peer and lifecycle
    .peer =
        {
            .BTM_CancelRemoteDeviceName = BTM_CancelRemoteDeviceName,
            .BTM_IsAclConnectionUp = BTM_IsAclConnectionUp,
            .BTM_ReadConnectedTransportAddress =
                BTM_ReadConnectedTransportAddress,
            .BTM_ReadDevInfo = BTM_ReadDevInfo,
            .BTM_ReadRemoteDeviceName = BTM_ReadRemoteDeviceName,
            .BTM_ReadRemoteFeatures = BTM_ReadRemoteFeatures,
            .BTM_SetEncryption = BTM_SetEncryption,
            .BTM_GetMaxPacketSize = BTM_GetMaxPacketSize,
            .BTM_ReadRemoteVersion = BTM_ReadRemoteVersion,
        },

    .link_policy =
        {
            .BTM_GetRole = BTM_GetRole,
            .BTM_SetPowerMode = BTM_SetPowerMode,
            .BTM_SetSsrParams = BTM_SetSsrParams,
            .BTM_SwitchRoleToCentral = BTM_SwitchRoleToCentral,
            .BTM_WritePageTimeout = BTM_WritePageTimeout,
            .BTM_block_role_switch_for = BTM_block_role_switch_for,
            .BTM_block_sniff_mode_for = BTM_block_sniff_mode_for,
            .BTM_default_unblock_role_switch = BTM_default_unblock_role_switch,
            .BTM_unblock_role_switch_for = BTM_unblock_role_switch_for,
            .BTM_unblock_sniff_mode_for = BTM_unblock_sniff_mode_for,
        },

    .link_controller =
        {
            .BTM_GetLinkSuperTout = BTM_GetLinkSuperTout,
            .BTM_ReadRSSI = BTM_ReadRSSI,
            .BTM_SetDefaultLinkSuperTout = BTM_SetDefaultLinkSuperTout,
        },

    .security =
        {
            .BTM_ConfirmReqReply = BTM_ConfirmReqReply,
            .BTM_PINCodeReply = BTM_PINCodeReply,
            .BTM_RemoteOobDataReply = BTM_RemoteOobDataReply,
            .BTM_SecAddBleDevice = BTM_SecAddBleDevice,
            .BTM_SecAddBleKey = BTM_SecAddBleKey,
            .BTM_SecAddDevice = BTM_SecAddDevice,
            .BTM_SecAddRmtNameNotifyCallback = BTM_SecAddRmtNameNotifyCallback,
            .BTM_SecBond = BTM_SecBond,
            .BTM_SecBondCancel = BTM_SecBondCancel,
            .BTM_SecClearSecurityFlags = BTM_SecClearSecurityFlags,
            .BTM_SecClrServiceByPsm = BTM_SecClrServiceByPsm,
            .BTM_SecDeleteDevice = BTM_SecDeleteDevice,
            .BTM_SecDeleteRmtNameNotifyCallback =
                BTM_SecDeleteRmtNameNotifyCallback,
            .BTM_SecReadDevName = BTM_SecReadDevName,
            .BTM_SecRegister = BTM_SecRegister,
        },

    .ble =
        {
            .BTM_BleConfirmReply = BTM_BleConfirmReply,
            .BTM_BleGetEnergyInfo = BTM_BleGetEnergyInfo,
            .BTM_BleLoadLocalKeys = BTM_BleLoadLocalKeys,
            .BTM_BleObserve = BTM_BleObserve,
            .BTM_BlePasskeyReply = BTM_BlePasskeyReply,
            .BTM_BleReadControllerFeatures = BTM_BleReadControllerFeatures,
            .BTM_BleSetPhy = BTM_BleSetPhy,
            .BTM_BleSetPrefConnParams = BTM_BleSetPrefConnParams,
            .BTM_SetBleDataLength = BTM_SetBleDataLength,
        },

    .sco =
        {
            .BTM_CreateSco = BTM_CreateSco,
            .BTM_EScoConnRsp = BTM_EScoConnRsp,
            .BTM_GetNumScoLinks = BTM_GetNumScoLinks,
            .BTM_RegForEScoEvts = BTM_RegForEScoEvts,
            .BTM_RemoveSco = BTM_RemoveSco,
            .BTM_SetEScoMode = BTM_SetEScoMode,
            .BTM_WriteVoiceSettings = BTM_WriteVoiceSettings,
        },

    .local =
        {
            .BTM_ReadLocalDeviceNameFromController =
                BTM_ReadLocalDeviceNameFromController,
            .BTM_SetDeviceClass = BTM_SetDeviceClass,
            .BTM_SetLocalDeviceName = BTM_SetLocalDeviceName,
            .BTM_IsDeviceUp = BTM_IsDeviceUp,
            .BTM_ReadDeviceClass = BTM_ReadDeviceClass,
        },

    .eir =
        {
            .BTM_GetEirSupportedServices = BTM_GetEirSupportedServices,
            .BTM_GetEirUuidList = BTM_GetEirUuidList,
            .BTM_RemoveEirService = BTM_RemoveEirService,
            .BTM_WriteEIR = BTM_WriteEIR,
        },
    .db =
        {
            .BTM_InqDbRead = BTM_InqDbRead,
            .BTM_InqDbFirst = BTM_InqDbFirst,
            .BTM_InqDbNext = BTM_InqDbNext,
            .BTM_ClearInqDb = BTM_ClearInqDb,
        },
};

struct btm_client_interface_s& get_btm_client_interface() {
  return btm_client_interface;
}
