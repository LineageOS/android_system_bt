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
#ifndef BTM_API_H
#define BTM_API_H

#include "bt_target.h"
#include "sdp_api.h"
#include "hcidefs.h"

#include "smp_api.h"

#include "btm_api_types.h"

/*****************************************************************************
**  EXTERNAL FUNCTION DECLARATIONS
*****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
**  DEVICE CONTROL and COMMON FUNCTIONS
*****************************************************************************/

/*******************************************************************************
**
** Function         BTM_DeviceReset
**
** Description      This function is called to reset the controller.The Callback function
**                  if provided is called when startup of the device has
**                  completed.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_DeviceReset (tBTM_CMPL_CB *p_cb);


/*******************************************************************************
**
** Function         BTM_HCI_Reset
**
** Description      This function is called to send reset command to the controller.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_HCI_Reset (void);

/*******************************************************************************
**
** Function         BTM_IsDeviceUp
**
** Description      This function is called to check if the device is up.
**
** Returns          TRUE if device is up, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_IsDeviceUp (void);


/*******************************************************************************
**
** Function         BTM_SetLocalDeviceName
**
** Description      This function is called to set the local device name.
**
** Returns          BTM_CMD_STARTED if successful, otherwise an error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetLocalDeviceName (char *p_name);

/*******************************************************************************
**
** Function         BTM_SetDeviceClass
**
** Description      This function is called to set the local device class
**
** Returns          BTM_SUCCESS if successful, otherwise an error
**
*******************************************************************************/
extern tBTM_STATUS  BTM_SetDeviceClass (DEV_CLASS dev_class);


/*******************************************************************************
**
** Function         BTM_ReadLocalDeviceName
**
** Description      This function is called to read the local device name.
**
** Returns          status of the operation
**                  If success, BTM_SUCCESS is returned and p_name points stored
**                              local device name
**                  If BTM doesn't store local device name, BTM_NO_RESOURCES is
**                              is returned and p_name is set to NULL
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadLocalDeviceName (char **p_name);

/*******************************************************************************
**
** Function         BTM_ReadLocalDeviceNameFromController
**
** Description      Get local device name from controller. Do not use cached
**                  name (used to get chip-id prior to btm reset complete).
**
** Returns          BTM_CMD_STARTED if successful, otherwise an error
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadLocalDeviceNameFromController (tBTM_CMPL_CB *p_rln_cmpl_cback);

/*******************************************************************************
**
** Function         BTM_ReadDeviceClass
**
** Description      This function is called to read the local device class
**
** Returns          pointer to the device class
**
*******************************************************************************/
extern UINT8 *BTM_ReadDeviceClass (void);


/*******************************************************************************
**
** Function         BTM_ReadLocalFeatures
**
** Description      This function is called to read the local features
**
** Returns          pointer to the local features string
**
*******************************************************************************/
extern UINT8 *BTM_ReadLocalFeatures (void);

/*******************************************************************************
**
** Function         BTM_RegisterForDeviceStatusNotif
**
** Description      This function is called to register for device status
**                  change notifications.
**
** Returns          pointer to previous caller's callback function or NULL if first
**                  registration.
**
*******************************************************************************/
extern tBTM_DEV_STATUS_CB *BTM_RegisterForDeviceStatusNotif (tBTM_DEV_STATUS_CB *p_cb);


/*******************************************************************************
**
** Function         BTM_RegisterForVSEvents
**
** Description      This function is called to register/deregister for vendor
**                  specific HCI events.
**
**                  If is_register=TRUE, then the function will be registered;
**                  if is_register=FALSE, then the function will be deregistered.
**
** Returns          BTM_SUCCESS if successful,
**                  BTM_BUSY if maximum number of callbacks have already been
**                           registered.
**
*******************************************************************************/
extern tBTM_STATUS BTM_RegisterForVSEvents (tBTM_VS_EVT_CB *p_cb, BOOLEAN is_register);


/*******************************************************************************
**
** Function         BTM_Hci_Raw_Command
**
** Description      Send a HCI RAW started testingcommand to the controller.
**
*******************************************************************************/
extern tBTM_STATUS BTM_Hci_Raw_Command(UINT16 opcode,
                                                         UINT8 param_len,
                                                         UINT8 *p_param_buf,
                                                         tBTM_RAW_CMPL_CB *p_cb);

/*******************************************************************************
**
** Function         BTM_VendorSpecificCommand
**
** Description      Send a vendor specific HCI command to the controller.
**
** Returns
**      BTM_SUCCESS         Command sent. Does not expect command complete
**                              event. (command cmpl callback param is NULL)
**      BTM_CMD_STARTED     Command sent. Waiting for command cmpl event.
**      BTM_BUSY            Command not sent. Waiting for cmd cmpl event for
**                              prior command.
**
*******************************************************************************/
extern tBTM_STATUS BTM_VendorSpecificCommand(UINT16 opcode,
                                             UINT8 param_len,
                                             UINT8 *p_param_buf,
                                             tBTM_VSC_CMPL_CB *p_cb);


/*******************************************************************************
**
** Function         BTM_AllocateSCN
**
** Description      Look through the Server Channel Numbers for a free one to be
**                  used with an RFCOMM connection.
**
** Returns          Allocated SCN number or 0 if none.
**
*******************************************************************************/
extern UINT8 BTM_AllocateSCN(void);

/*******************************************************************************
**
** Function         BTM_TryAllocateSCN
**
** Description      Try to allocate a fixed server channel
**
** Returns          Returns TRUE if server channel was available
**
*******************************************************************************/
extern BOOLEAN BTM_TryAllocateSCN(UINT8 scn);


/*******************************************************************************
**
** Function         BTM_FreeSCN
**
** Description      Free the specified SCN.
**
** Returns          TRUE if successful, FALSE if SCN is not in use or invalid
**
*******************************************************************************/
extern BOOLEAN BTM_FreeSCN(UINT8 scn);


/*******************************************************************************
**
** Function         BTM_SetTraceLevel
**
** Description      This function sets the trace level for BTM.  If called with
**                  a value of 0xFF, it simply returns the current trace level.
**
** Returns          The new or current trace level
**
*******************************************************************************/
extern UINT8 BTM_SetTraceLevel (UINT8 new_level);


/*******************************************************************************
**
** Function         BTM_WritePageTimeout
**
** Description      Send HCI Wite Page Timeout.
**
** Returns
**      BTM_SUCCESS         Command sent.
**      BTM_NO_RESOURCES    If out of resources to send the command.
**
*******************************************************************************/
extern tBTM_STATUS BTM_WritePageTimeout(UINT16 timeout);

/*******************************************************************************
**
** Function         BTM_WriteVoiceSettings
**
** Description      Send HCI Write Voice Settings command.
**                  See hcidefs.h for settings bitmask values.
**
** Returns
**      BTM_SUCCESS         Command sent.
**      BTM_NO_RESOURCES     If out of resources to send the command.
**
**
*******************************************************************************/
extern tBTM_STATUS BTM_WriteVoiceSettings(UINT16 settings);

/*******************************************************************************
**
** Function         BTM_EnableTestMode
**
** Description      Send HCI the enable device under test command.
**
**                  Note: Controller can only be taken out of this mode by
**                      resetting the controller.
**
** Returns
**      BTM_SUCCESS         Command sent.
**      BTM_NO_RESOURCES    If out of resources to send the command.
**
**
*******************************************************************************/
extern tBTM_STATUS BTM_EnableTestMode(void);


/*****************************************************************************
**  DEVICE DISCOVERY FUNCTIONS - Inquiry, Remote Name, Discovery, Class of Device
*****************************************************************************/

/*******************************************************************************
**
** Function         BTM_SetDiscoverability
**
** Description      This function is called to set the device into or out of
**                  discoverable mode. Discoverable mode means inquiry
**                  scans are enabled.  If a value of '0' is entered for window or
**                  interval, the default values are used.
**
** Returns          BTM_SUCCESS if successful
**                  BTM_BUSY if a setting of the filter is already in progress
**                  BTM_NO_RESOURCES if couldn't get a memory pool buffer
**                  BTM_ILLEGAL_VALUE if a bad parameter was detected
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS  BTM_SetDiscoverability (UINT16 inq_mode, UINT16 window,
                                            UINT16 interval);


/*******************************************************************************
**
** Function         BTM_ReadDiscoverability
**
** Description      This function is called to read the current discoverability
**                  mode of the device.
**
** Output Params:   p_window - current inquiry scan duration
**                  p_interval - current inquiry scan interval
**
** Returns          BTM_NON_DISCOVERABLE, BTM_LIMITED_DISCOVERABLE, or
**                  BTM_GENERAL_DISCOVERABLE
**
*******************************************************************************/
extern UINT16       BTM_ReadDiscoverability (UINT16 *p_window,
                                             UINT16 *p_interval);


/*******************************************************************************
**
** Function         BTM_SetPeriodicInquiryMode
**
** Description      This function is called to set the device periodic inquiry mode.
**                  If the duration is zero, the periodic inquiry mode is cancelled.
**
** Parameters:      p_inqparms - pointer to the inquiry information
**                      mode - GENERAL or LIMITED inquiry
**                      duration - length in 1.28 sec intervals (If '0', the inquiry is CANCELLED)
**                      max_resps - maximum amount of devices to search for before ending the inquiry
**                      filter_cond_type - BTM_CLR_INQUIRY_FILTER, BTM_FILTER_COND_DEVICE_CLASS, or
**                                         BTM_FILTER_COND_BD_ADDR
**                      filter_cond - value for the filter (based on filter_cond_type)
**
**                  max_delay - maximum amount of time between successive inquiries
**                  min_delay - minimum amount of time between successive inquiries
**                  p_results_cb - callback returning pointer to results (tBTM_INQ_RESULTS)
**
** Returns          BTM_CMD_STARTED if successfully started
**                  BTM_ILLEGAL_VALUE if a bad parameter is detected
**                  BTM_NO_RESOURCES if could not allocate a message buffer
**                  BTM_SUCCESS - if cancelling the periodic inquiry
**                  BTM_BUSY - if an inquiry is already active
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS  BTM_SetPeriodicInquiryMode (tBTM_INQ_PARMS *p_inqparms,
                                                UINT16 max_delay, UINT16 min_delay,
                                                tBTM_INQ_RESULTS_CB *p_results_cb);


/*******************************************************************************
**
** Function         BTM_StartInquiry
**
** Description      This function is called to start an inquiry.
**
** Parameters:      p_inqparms - pointer to the inquiry information
**                      mode - GENERAL or LIMITED inquiry
**                      duration - length in 1.28 sec intervals (If '0', the inquiry is CANCELLED)
**                      max_resps - maximum amount of devices to search for before ending the inquiry
**                      filter_cond_type - BTM_CLR_INQUIRY_FILTER, BTM_FILTER_COND_DEVICE_CLASS, or
**                                         BTM_FILTER_COND_BD_ADDR
**                      filter_cond - value for the filter (based on filter_cond_type)
**
**                  p_results_cb   - Pointer to the callback routine which gets called
**                                upon receipt of an inquiry result. If this field is
**                                NULL, the application is not notified.
**
**                  p_cmpl_cb   - Pointer to the callback routine which gets called
**                                upon completion.  If this field is NULL, the
**                                application is not notified when completed.
** Returns          tBTM_STATUS
**                  BTM_CMD_STARTED if successfully initiated
**                  BTM_BUSY if already in progress
**                  BTM_ILLEGAL_VALUE if parameter(s) are out of range
**                  BTM_NO_RESOURCES if could not allocate resources to start the command
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS  BTM_StartInquiry (tBTM_INQ_PARMS *p_inqparms,
                                      tBTM_INQ_RESULTS_CB *p_results_cb,
                                      tBTM_CMPL_CB *p_cmpl_cb);


/*******************************************************************************
**
** Function         BTM_IsInquiryActive
**
** Description      This function returns a bit mask of the current inquiry state
**
** Returns          BTM_INQUIRY_INACTIVE if inactive (0)
**                  BTM_LIMITED_INQUIRY_ACTIVE if a limted inquiry is active
**                  BTM_GENERAL_INQUIRY_ACTIVE if a general inquiry is active
**                  BTM_PERIODIC_INQUIRY_ACTIVE if a periodic inquiry is active
**
*******************************************************************************/
extern UINT16 BTM_IsInquiryActive (void);


/*******************************************************************************
**
** Function         BTM_CancelInquiry
**
** Description      This function cancels an inquiry if active
**
** Returns          BTM_SUCCESS if successful
**                  BTM_NO_RESOURCES if could not allocate a message buffer
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS BTM_CancelInquiry(void);


/*******************************************************************************
**
** Function         BTM_CancelPeriodicInquiry
**
** Description      This function cancels a periodic inquiry
**
** Returns
**                  BTM_NO_RESOURCES if could not allocate a message buffer
**                  BTM_SUCCESS - if cancelling the periodic inquiry
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS BTM_CancelPeriodicInquiry(void);


/*******************************************************************************
**
** Function         BTM_SetConnectability
**
** Description      This function is called to set the device into or out of
**                  connectable mode. Discoverable mode means page scans enabled.
**
** Returns          BTM_SUCCESS if successful
**                  BTM_ILLEGAL_VALUE if a bad parameter is detected
**                  BTM_NO_RESOURCES if could not allocate a message buffer
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetConnectability (UINT16 page_mode, UINT16 window,
                                          UINT16 interval);


/*******************************************************************************
**
** Function         BTM_ReadConnectability
**
** Description      This function is called to read the current discoverability
**                  mode of the device.
** Output Params    p_window - current page scan duration
**                  p_interval - current time between page scans
**
** Returns          BTM_NON_CONNECTABLE or BTM_CONNECTABLE
**
*******************************************************************************/
extern UINT16 BTM_ReadConnectability (UINT16 *p_window, UINT16 *p_interval);


/*******************************************************************************
**
** Function         BTM_SetInquiryMode
**
** Description      This function is called to set standard, with RSSI
**                  mode or extended of the inquiry for local device.
**
** Input Params:    BTM_INQ_RESULT_STANDARD, BTM_INQ_RESULT_WITH_RSSI or
**                  BTM_INQ_RESULT_EXTENDED
**
** Returns          BTM_SUCCESS if successful
**                  BTM_NO_RESOURCES if couldn't get a memory pool buffer
**                  BTM_ILLEGAL_VALUE if a bad parameter was detected
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS  BTM_SetInquiryMode (UINT8 mode);

/*******************************************************************************
**
** Function         BTM_SetInquiryScanType
**
** Description      This function is called to set the iquiry scan-type to
**                  standard or interlaced.
**
** Input Params:    BTM_SCAN_TYPE_STANDARD or BTM_SCAN_TYPE_INTERLACED
**
** Returns          BTM_SUCCESS if successful
**                  BTM_MODE_UNSUPPORTED if not a 1.2 device
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetInquiryScanType (UINT16 scan_type);

/*******************************************************************************
**
** Function         BTM_SetPageScanType
**
** Description      This function is called to set the page scan-type to
**                  standard or interlaced.
**
** Input Params:    BTM_SCAN_TYPE_STANDARD or BTM_SCAN_TYPE_INTERLACED
**
** Returns          BTM_SUCCESS if successful
**                  BTM_MODE_UNSUPPORTED if not a 1.2 device
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/

extern tBTM_STATUS BTM_SetPageScanType (UINT16 scan_type);

/*******************************************************************************
**
** Function         BTM_ReadRemoteDeviceName
**
** Description      This function initiates a remote device HCI command to the
**                  controller and calls the callback when the process has completed.
**
** Input Params:    remote_bda      - device address of name to retrieve
**                  p_cb            - callback function called when BTM_CMD_STARTED
**                                    is returned.
**                                    A pointer to tBTM_REMOTE_DEV_NAME is passed to the
**                                    callback.
**
** Returns
**                  BTM_CMD_STARTED is returned if the request was successfully sent
**                                  to HCI.
**                  BTM_BUSY if already in progress
**                  BTM_UNKNOWN_ADDR if device address is bad
**                  BTM_NO_RESOURCES if could not allocate resources to start the command
**                  BTM_WRONG_MODE if the device is not up.
**
*******************************************************************************/
extern tBTM_STATUS  BTM_ReadRemoteDeviceName (BD_ADDR remote_bda,
                                              tBTM_CMPL_CB *p_cb,
                                              tBT_TRANSPORT transport);


/*******************************************************************************
**
** Function         BTM_CancelRemoteDeviceName
**
** Description      This function initiates the cancel request for the specified
**                  remote device.
**
** Input Params:    None
**
** Returns
**                  BTM_CMD_STARTED is returned if the request was successfully sent
**                                  to HCI.
**                  BTM_NO_RESOURCES if could not allocate resources to start the command
**                  BTM_WRONG_MODE if there is not an active remote name request.
**
*******************************************************************************/
extern tBTM_STATUS  BTM_CancelRemoteDeviceName (void);

/*******************************************************************************
**
** Function         BTM_ReadRemoteVersion
**
** Description      This function is called to read a remote device's version
**
** Returns          BTM_SUCCESS if successful, otherwise an error
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadRemoteVersion (BD_ADDR addr,
                                          UINT8 *lmp_version,
                                          UINT16 *manufacturer,
                                          UINT16 *lmp_sub_version);

/*******************************************************************************
**
** Function         BTM_ReadRemoteFeatures
**
** Description      This function is called to read a remote device's
**                  supported features mask (features mask located at page 0)
**
**                  Note: The size of device features mask page is
**                  BTM_FEATURE_BYTES_PER_PAGE bytes.
**
** Returns          pointer to the remote supported features mask
**
*******************************************************************************/
extern UINT8 *BTM_ReadRemoteFeatures (BD_ADDR addr);

/*******************************************************************************
**
** Function         BTM_ReadRemoteExtendedFeatures
**
** Description      This function is called to read a specific extended features
**                  page of the remote device
**
**                  Note1: The size of device features mask page is
**                  BTM_FEATURE_BYTES_PER_PAGE bytes.
**                  Note2: The valid device features mask page number depends on
**                  the remote device capabilities. It is expected to be in the
**                  range [0 - BTM_EXT_FEATURES_PAGE_MAX].

** Returns          pointer to the remote extended features mask
**                  or NULL if page_number is not valid
**
*******************************************************************************/
extern UINT8 *BTM_ReadRemoteExtendedFeatures (BD_ADDR addr, UINT8 page_number);

/*******************************************************************************
**
** Function         BTM_ReadNumberRemoteFeaturesPages
**
** Description      This function is called to retrieve the number of feature pages
**                  read from the remote device
**
** Returns          number of features pages read from the remote device
**
*******************************************************************************/
extern UINT8 BTM_ReadNumberRemoteFeaturesPages (BD_ADDR addr);

/*******************************************************************************
**
** Function         BTM_ReadAllRemoteFeatures
**
** Description      This function is called to read all features of the remote device
**
** Returns          pointer to the byte[0] of the page[0] of the remote device
**                  feature mask.
**
** Note:            the function returns the pointer to the array of the size
**                  BTM_FEATURE_BYTES_PER_PAGE * (BTM_EXT_FEATURES_PAGE_MAX + 1).
**
*******************************************************************************/
extern UINT8 *BTM_ReadAllRemoteFeatures (BD_ADDR addr);

/*******************************************************************************
**
** Function         BTM_InqDbRead
**
** Description      This function looks through the inquiry database for a match
**                  based on Bluetooth Device Address. This is the application's
**                  interface to get the inquiry details of a specific BD address.
**
** Returns          pointer to entry, or NULL if not found
**
*******************************************************************************/
extern tBTM_INQ_INFO *BTM_InqDbRead (const BD_ADDR p_bda);


/*******************************************************************************
**
** Function         BTM_InqDbFirst
**
** Description      This function looks through the inquiry database for the first
**                  used entry, and returns that. This is used in conjunction with
**                  BTM_InqDbNext by applications as a way to walk through the
**                  inquiry database.
**
** Returns          pointer to first in-use entry, or NULL if DB is empty
**
*******************************************************************************/
extern tBTM_INQ_INFO *BTM_InqDbFirst (void);


/*******************************************************************************
**
** Function         BTM_InqDbNext
**
** Description      This function looks through the inquiry database for the next
**                  used entry, and returns that.  If the input parameter is NULL,
**                  the first entry is returned.
**
** Returns          pointer to next in-use entry, or NULL if no more found.
**
*******************************************************************************/
extern tBTM_INQ_INFO *BTM_InqDbNext (tBTM_INQ_INFO *p_cur);


/*******************************************************************************
**
** Function         BTM_ClearInqDb
**
** Description      This function is called to clear out a device or all devices
**                  from the inquiry database.
**
** Parameter        p_bda - (input) BD_ADDR ->  Address of device to clear
**                                              (NULL clears all entries)
**
** Returns          BTM_BUSY if an inquiry, get remote name, or event filter
**                          is active, otherwise BTM_SUCCESS
**
*******************************************************************************/
extern tBTM_STATUS  BTM_ClearInqDb (BD_ADDR p_bda);

/*******************************************************************************
**
** Function         BTM_ReadInquiryRspTxPower
**
** Description      This command will read the inquiry Transmit Power level used
**                  to transmit the FHS and EIR data packets.
**                  This can be used directly in the Tx Power Level EIR data type.
**
** Returns          BTM_SUCCESS if successful
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadInquiryRspTxPower (tBTM_CMPL_CB *p_cb);

/*******************************************************************************
**
** Function         BTM_StartDiscovery
**
** Description      This function is called by an application (or profile)
**                  when it wants to trigger an service discovery using the
**                  BTM's discovery database.
**
** Returns          tBTM_STATUS
**                      BTM_CMD_STARTED if the discovery was initiated
**                      BTM_BUSY if one is already in progress
**                      BTM_UNKNOWN_ADDR if no addresses are in the INQ DB
**                      BTM_ERR_PROCESSING if err initiating the command
**
*******************************************************************************/
extern tBTM_STATUS BTM_StartDiscovery (tBTM_CMPL_CB *p_cmpl_cb,
                                       BD_ADDR_PTR p_rem_addr);


/*******************************************************************************
**
** Function         BTM_FindAttribute
**
** Description      This function is called by an application (or profile)
**                  when it wants to see if an attribute exists in the BTM
**                  discovery database.
**
** Returns          Pointer to matching record, or NULL
**
*******************************************************************************/
extern tSDP_DISC_REC *BTM_FindAttribute (UINT16 attr_id,
                                         tSDP_DISC_REC *p_start_rec);


/*******************************************************************************
**
** Function         BTM_FindService
**
** Description      This function is called by an application (or profile)
**                  when it wants to see if a service exists in the BTM
**                  discovery database.
**
** Returns          Pointer to matching record, or NULL
**
*******************************************************************************/
extern tSDP_DISC_REC *BTM_FindService (UINT16 service_uuid,
                                       tSDP_DISC_REC *p_start_rec);


/*******************************************************************************
**
** Function         BTM_SetDiscoveryParams
**
** Description      This function is called to set the BTM default discovery parameters.
**                  These UUID and attribute filters are used during the call to
**                  BTM_StartDiscovery.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetDiscoveryParams (UINT16 num_uuid, tSDP_UUID *p_uuid_list,
                                    UINT16 num_attr, UINT16 *p_attr_list);


/*****************************************************************************
**  ACL CHANNEL MANAGEMENT FUNCTIONS
*****************************************************************************/
/*******************************************************************************
**
** Function         BTM_SetLinkPolicy
**
** Description      Create and send HCI "Write Policy Set" command
**
** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetLinkPolicy (BD_ADDR remote_bda,
                                      UINT16 *settings);

/*******************************************************************************
**
** Function         BTM_SetDefaultLinkPolicy
**
** Description      Set the default value for HCI "Write Policy Set" command
**                  to use when an ACL link is created.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetDefaultLinkPolicy (UINT16 settings);


/*******************************************************************************
**
** Function         BTM_SetDefaultLinkSuperTout
**
** Description      Set the default value for HCI "Write Link Supervision Timeout"
**                  command to use when an ACL link is created.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetDefaultLinkSuperTout (UINT16 timeout);


/*******************************************************************************
**
** Function         BTM_SetLinkSuperTout
**
** Description      Create and send HCI "Write Link Supervision Timeout" command
**
** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetLinkSuperTout (BD_ADDR remote_bda,
                                         UINT16 timeout);
/*******************************************************************************
**
** Function         BTM_GetLinkSuperTout
**
** Description      Read the link supervision timeout value of the connection
**
** Returns          status of the operation
**
*******************************************************************************/
extern tBTM_STATUS BTM_GetLinkSuperTout (BD_ADDR remote_bda,
                                         UINT16 *p_timeout);

/*******************************************************************************
**
** Function         BTM_IsAclConnectionUp
**
** Description      This function is called to check if an ACL connection exists
**                  to a specific remote BD Address.
**
** Returns          TRUE if connection is up, else FALSE.
**
*******************************************************************************/
extern BOOLEAN BTM_IsAclConnectionUp (BD_ADDR remote_bda, tBT_TRANSPORT transport);


/*******************************************************************************
**
** Function         BTM_GetRole
**
** Description      This function is called to get the role of the local device
**                  for the ACL connection with the specified remote device
**
** Returns          BTM_SUCCESS if connection exists.
**                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
**
*******************************************************************************/
extern tBTM_STATUS BTM_GetRole (BD_ADDR remote_bd_addr, UINT8 *p_role);



/*******************************************************************************
**
** Function         BTM_SwitchRole
**
** Description      This function is called to switch role between master and
**                  slave.  If role is already set it will do nothing.  If the
**                  command was initiated, the callback function is called upon
**                  completion.
**
** Returns          BTM_SUCCESS if already in specified role.
**                  BTM_CMD_STARTED if command issued to controller.
**                  BTM_NO_RESOURCES if couldn't allocate memory to issue command
**                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
**                  BTM_MODE_UNSUPPORTED if local device does not support role switching
**
*******************************************************************************/
extern tBTM_STATUS BTM_SwitchRole (BD_ADDR remote_bd_addr,
                                   UINT8 new_role,
                                   tBTM_CMPL_CB *p_cb);

/*******************************************************************************
**
** Function         BTM_ReadRSSI
**
** Description      This function is called to read the link policy settings.
**                  The address of link policy results are returned in the callback.
**                  (tBTM_RSSI_RESULTS)
**
** Returns          BTM_CMD_STARTED if command issued to controller.
**                  BTM_NO_RESOURCES if couldn't allocate memory to issue command
**                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
**                  BTM_BUSY if command is already in progress
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadRSSI (BD_ADDR remote_bda, tBTM_CMPL_CB *p_cb);


/*******************************************************************************
**
** Function         BTM_ReadTxPower
**
** Description      This function is called to read the current connection
**                  TX power of the connection. The TX power level results
**                  are returned in the callback.
**                  (tBTM_RSSI_RESULTS)
**
** Returns          BTM_CMD_STARTED if command issued to controller.
**                  BTM_NO_RESOURCES if couldn't allocate memory to issue command
**                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
**                  BTM_BUSY if command is already in progress
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadTxPower (BD_ADDR remote_bda,
                                    tBT_TRANSPORT transport, tBTM_CMPL_CB *p_cb);

/*******************************************************************************
**
** Function         BTM_ReadLinkQuality
**
** Description      This function is called to read the link quality.
**                  The value of the link quality is returned in the callback.
**                  (tBTM_LINK_QUALITY_RESULTS)
**
** Returns          BTM_CMD_STARTED if command issued to controller.
**                  BTM_NO_RESOURCES if couldn't allocate memory to issue command
**                  BTM_UNKNOWN_ADDR if no active link with bd addr specified
**                  BTM_BUSY if command is already in progress
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadLinkQuality (BD_ADDR remote_bda, tBTM_CMPL_CB *p_cb);

/*******************************************************************************
**
** Function         BTM_RegBusyLevelNotif
**
** Description      This function is called to register a callback to receive
**                  busy level change events.
**
** Returns          BTM_SUCCESS if successfully registered, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_RegBusyLevelNotif (tBTM_BL_CHANGE_CB *p_cb, UINT8 *p_level,
                                          tBTM_BL_EVENT_MASK evt_mask);

/*******************************************************************************
**
** Function         BTM_AclRegisterForChanges
**
** Description      This function is called to register a callback to receive
**                  ACL database change events, i.e. new connection or removed.
**
** Returns          BTM_SUCCESS if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_AclRegisterForChanges (tBTM_ACL_DB_CHANGE_CB *p_cb);

/*******************************************************************************
**
** Function         BTM_GetNumAclLinks
**
** Description      This function is called to count the number of
**                  ACL links that are active.
**
** Returns          UINT16  Number of active ACL links
**
*******************************************************************************/
extern UINT16 BTM_GetNumAclLinks (void);

/*******************************************************************************
**
** Function         BTM_SetQoS
**
** Description      This function is called to setup QoS
**
** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetQoS(BD_ADDR bd, FLOW_SPEC *p_flow,
                              tBTM_CMPL_CB *p_cb);


/*****************************************************************************
**  (e)SCO CHANNEL MANAGEMENT FUNCTIONS
*****************************************************************************/
/*******************************************************************************
**
** Function         BTM_CreateSco
**
** Description      This function is called to create an SCO connection. If the
**                  "is_orig" flag is TRUE, the connection will be originated,
**                  otherwise BTM will wait for the other side to connect.
**
** Returns          BTM_UNKNOWN_ADDR if the ACL connection is not up
**                  BTM_BUSY         if another SCO being set up to
**                                   the same BD address
**                  BTM_NO_RESOURCES if the max SCO limit has been reached
**                  BTM_CMD_STARTED  if the connection establishment is started.
**                                   In this case, "*p_sco_inx" is filled in
**                                   with the sco index used for the connection.
**
*******************************************************************************/
extern tBTM_STATUS BTM_CreateSco (BD_ADDR remote_bda, BOOLEAN is_orig,
                                  UINT16 pkt_types, UINT16 *p_sco_inx,
                                  tBTM_SCO_CB *p_conn_cb,
                                  tBTM_SCO_CB *p_disc_cb);


/*******************************************************************************
**
** Function         BTM_RemoveSco
**
** Description      This function is called to remove a specific SCO connection.
**
** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_RemoveSco (UINT16 sco_inx);


/*******************************************************************************
**
** Function         BTM_SetScoPacketTypes
**
** Description      This function is called to set the packet types used for
**                  a specific SCO connection,
**
** Parameters       pkt_types - One or more of the following
**                  BTM_SCO_PKT_TYPES_MASK_HV1
**                  BTM_SCO_PKT_TYPES_MASK_HV2
**                  BTM_SCO_PKT_TYPES_MASK_HV3
**                  BTM_SCO_PKT_TYPES_MASK_EV3
**                  BTM_SCO_PKT_TYPES_MASK_EV4
**                  BTM_SCO_PKT_TYPES_MASK_EV5
**
**                  BTM_SCO_LINK_ALL_MASK   - enables all supported types
**
** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetScoPacketTypes (UINT16 sco_inx, UINT16 pkt_types);


/*******************************************************************************
**
** Function         BTM_ReadScoPacketTypes
**
** Description      This function is read the packet types used for a specific
**                  SCO connection.
**
** Returns       One or more of the following (bitmask)
**                  BTM_SCO_PKT_TYPES_MASK_HV1
**                  BTM_SCO_PKT_TYPES_MASK_HV2
**                  BTM_SCO_PKT_TYPES_MASK_HV3
**                  BTM_SCO_PKT_TYPES_MASK_EV3
**                  BTM_SCO_PKT_TYPES_MASK_EV4
**                  BTM_SCO_PKT_TYPES_MASK_EV5
**
** Returns          packet types supported for the connection
**
*******************************************************************************/
extern UINT16 BTM_ReadScoPacketTypes (UINT16 sco_inx);


/*******************************************************************************
**
** Function         BTM_ReadDeviceScoPacketTypes
**
** Description      This function is read the SCO packet types that
**                  the device supports.
**
** Returns          packet types supported by the device.
**
*******************************************************************************/
extern UINT16 BTM_ReadDeviceScoPacketTypes (void);


/*******************************************************************************
**
** Function         BTM_ReadScoHandle
**
** Description      This function is used to read the HCI handle used for a specific
**                  SCO connection,
**
** Returns          handle for the connection, or 0xFFFF if invalid SCO index.
**
*******************************************************************************/
extern UINT16 BTM_ReadScoHandle (UINT16 sco_inx);


/*******************************************************************************
**
** Function         BTM_ReadScoBdAddr
**
** Description      This function is read the remote BD Address for a specific
**                  SCO connection,
**
** Returns          pointer to BD address or NULL if not known
**
*******************************************************************************/
extern UINT8 *BTM_ReadScoBdAddr (UINT16 sco_inx);


/*******************************************************************************
**
** Function         BTM_ReadScoDiscReason
**
** Description      This function is returns the reason why an (e)SCO connection
**                  has been removed. It contains the value until read, or until
**                  another (e)SCO connection has disconnected.
**
** Returns          HCI reason or BTM_INVALID_SCO_DISC_REASON if not set.
**
*******************************************************************************/
extern UINT16 BTM_ReadScoDiscReason (void);


/*******************************************************************************
**
** Function         BTM_SetEScoMode
**
** Description      This function sets up the negotiated parameters for SCO or
**                  eSCO, and sets as the default mode used for calls to
**                  BTM_CreateSco.  It can be called only when there are no
**                  active (e)SCO links.
**
** Returns          BTM_SUCCESS if the successful.
**                  BTM_BUSY if there are one or more active (e)SCO links.
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetEScoMode (tBTM_SCO_TYPE sco_mode,
                                    tBTM_ESCO_PARAMS *p_parms);

/*******************************************************************************
**
** Function         BTM_SetWBSCodec
**
** Description      This function sends command to the controller to setup
**                  WBS codec for the upcoming eSCO connection.
**
** Returns          BTM_SUCCESS.
**
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetWBSCodec (tBTM_SCO_CODEC_TYPE codec_type);

/*******************************************************************************
**
** Function         BTM_RegForEScoEvts
**
** Description      This function registers a SCO event callback with the
**                  specified instance.  It should be used to received
**                  connection indication events and change of link parameter
**                  events.
**
** Returns          BTM_SUCCESS if the successful.
**                  BTM_ILLEGAL_VALUE if there is an illegal sco_inx
**
*******************************************************************************/
extern tBTM_STATUS BTM_RegForEScoEvts (UINT16 sco_inx,
                                       tBTM_ESCO_CBACK *p_esco_cback);

/*******************************************************************************
**
** Function         BTM_ReadEScoLinkParms
**
** Description      This function returns the current eSCO link parameters for
**                  the specified handle.  This can be called anytime a connection
**                  is active, but is typically called after receiving the SCO
**                  opened callback.
**
**                  Note: If called over a 1.1 controller, only the packet types
**                        field has meaning.
**                  Note: If the upper layer doesn't know the current sco index,
**                  BTM_FIRST_ACTIVE_SCO_INDEX can be used as the first parameter to
**                  find the first active SCO index
**
** Returns          BTM_SUCCESS if returned data is valid connection.
**                  BTM_ILLEGAL_VALUE if no connection for specified sco_inx.
**                  BTM_MODE_UNSUPPORTED if local controller does not support
**                      1.2 specification.
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadEScoLinkParms (UINT16 sco_inx,
                                          tBTM_ESCO_DATA *p_parms);

/*******************************************************************************
**
** Function         BTM_ChangeEScoLinkParms
**
** Description      This function requests renegotiation of the parameters on
**                  the current eSCO Link.  If any of the changes are accepted
**                  by the controllers, the BTM_ESCO_CHG_EVT event is sent in
**                  the tBTM_ESCO_CBACK function with the current settings of
**                  the link. The callback is registered through the call to
**                  BTM_SetEScoMode.
**
**
** Returns          BTM_CMD_STARTED if command is successfully initiated.
**                  BTM_ILLEGAL_VALUE if no connection for specified sco_inx.
**                  BTM_NO_RESOURCES - not enough resources to initiate command.
**                  BTM_MODE_UNSUPPORTED if local controller does not support
**                      1.2 specification.
**
*******************************************************************************/
extern tBTM_STATUS BTM_ChangeEScoLinkParms (UINT16 sco_inx,
                                            tBTM_CHG_ESCO_PARAMS *p_parms);

/*******************************************************************************
**
** Function         BTM_EScoConnRsp
**
** Description      This function is called upon receipt of an (e)SCO connection
**                  request event (BTM_ESCO_CONN_REQ_EVT) to accept or reject
**                  the request. Parameters used to negotiate eSCO links.
**                  If p_parms is NULL, then values set through BTM_SetEScoMode
**                  are used.
**                  If the link type of the incoming request is SCO, then only
**                  the tx_bw, max_latency, content format, and packet_types are
**                  valid.  The hci_status parameter should be
**                  ([0x0] to accept, [0x0d..0x0f] to reject)
**
**
** Returns          void
**
*******************************************************************************/
extern void BTM_EScoConnRsp (UINT16 sco_inx, UINT8 hci_status,
                             tBTM_ESCO_PARAMS *p_parms);

/*******************************************************************************
**
** Function         BTM_GetNumScoLinks
**
** Description      This function returns the number of active SCO links.
**
** Returns          UINT8
**
*******************************************************************************/
extern UINT8 BTM_GetNumScoLinks (void);

/*****************************************************************************
**  SECURITY MANAGEMENT FUNCTIONS
*****************************************************************************/
/*******************************************************************************
**
** Function         BTM_SecRegister
**
** Description      Application manager calls this function to register for
**                  security services.  There can be one and only one application
**                  saving link keys.  BTM allows only first registration.
**
** Returns          TRUE if registered OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SecRegister (tBTM_APPL_INFO *p_cb_info);

/*******************************************************************************
**
** Function         BTM_SecRegisterLinkKeyNotificationCallback
**
** Description      Profiles can register to be notified when a new Link Key
**                  is generated per connection.
**
** Returns          TRUE if registered OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SecRegisterLinkKeyNotificationCallback(
                                                        tBTM_LINK_KEY_CALLBACK *p_callback);

/*******************************************************************************
**
** Function         BTM_SecAddRmtNameNotifyCallback
**
** Description      Profiles can register to be notified when name of the
**                  remote device is resolved (up to BTM_SEC_MAX_RMT_NAME_CALLBACKS).
**
** Returns          TRUE if registered OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SecAddRmtNameNotifyCallback (tBTM_RMT_NAME_CALLBACK *p_callback);


/*******************************************************************************
**
** Function         BTM_SecDeleteRmtNameNotifyCallback
**
** Description      A profile can deregister notification when a new Link Key
**                  is generated per connection.
**
** Returns          TRUE if OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SecDeleteRmtNameNotifyCallback (tBTM_RMT_NAME_CALLBACK *p_callback);

/*******************************************************************************
**
** Function         BTM_GetSecurityFlags
**
** Description      Get security flags for the device
**
** Returns          BOOLEAN TRUE or FALSE is device found
**
*******************************************************************************/
extern BOOLEAN BTM_GetSecurityFlags (BD_ADDR bd_addr, UINT8 * p_sec_flags);

/*******************************************************************************
**
** Function         BTM_GetSecurityFlagsByTransport
**
** Description      Get security flags for the device on a particular transport
**
** Parameters      bd_addr: BD address of remote device
**                  p_sec_flags : Out parameter to be filled with security flags for the connection
**                  transport :  Physical transport of the connection (BR/EDR or LE)
**
** Returns          BOOLEAN TRUE or FALSE is device found
**
*******************************************************************************/
extern BOOLEAN BTM_GetSecurityFlagsByTransport (BD_ADDR bd_addr,
                                                UINT8 * p_sec_flags, tBT_TRANSPORT transport);

/*******************************************************************************
**
** Function         BTM_ReadTrustedMask
**
** Description      Get trusted mask for the device
**
** Returns          NULL, if the device record is not found.
**                  otherwise, the trusted mask
**
*******************************************************************************/
extern UINT32 * BTM_ReadTrustedMask (BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_SetPinType
**
** Description      Set PIN type for the device.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetPinType (UINT8 pin_type, PIN_CODE pin_code, UINT8 pin_code_len);


/*******************************************************************************
**
** Function         BTM_SetPairableMode
**
** Description      Enable or disable pairing
**
** Parameters       allow_pairing - (TRUE or FALSE) whether or not the device
**                      allows pairing.
**                  connect_only_paired - (TRUE or FALSE) whether or not to
**                      only allow paired devices to connect.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetPairableMode (BOOLEAN allow_pairing, BOOLEAN connect_only_paired);

/*******************************************************************************
**
** Function         BTM_SetSecureConnectionsOnly
**
** Description      Enable or disable default treatment for Mode 4 Level 0 services
**
** Parameter        secure_connections_only_mode - (TRUE or FALSE)
**                  TRUE means that the device should treat Mode 4 Level 0 services as
**                  services of other levels.
**                  FALSE means that the device should provide default treatment for
**                  Mode 4 Level 0 services.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetSecureConnectionsOnly (BOOLEAN secure_connections_only_mode);

/*******************************************************************************
**
** Function         BTM_SetSecurityLevel
**
** Description      Register service security level with Security Manager.  Each
**                  service must register its requirements regardless of the
**                  security level that is used.  This API is called once for originators
**                  nad again for acceptors of connections.
**
** Returns          TRUE if registered OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SetSecurityLevel (BOOLEAN is_originator, char *p_name,
                                     UINT8 service_id, UINT16 sec_level,
                                     UINT16 psm, UINT32 mx_proto_id,
                                     UINT32 mx_chan_id);

/*******************************************************************************
**
** Function         BTM_SetOutService
**
** Description      This function is called to set the service for
**                  outgoing connection.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetOutService(BD_ADDR bd_addr, UINT8 service_id, UINT32 mx_chan_id);

/*******************************************************************************
**
** Function         BTM_SecClrService
**
** Description      Removes specified service record(s) from the security database.
**                  All service records with the specified name are removed.
**                  Typically used only by devices with limited RAM so that it can
**                  reuse an old security service record.
**                          records (except SDP).
**
** Returns          Number of records that were freed.
**
*******************************************************************************/
extern UINT8 BTM_SecClrService (UINT8 service_id);

/*******************************************************************************
**
** Function         BTM_SecAddDevice
**
** Description      Add/modify device.  This function will be normally called
**                  during host startup to restore all required information
**                  stored in the NVRAM.
**                  dev_class, bd_name, link_key, and features are NULL if unknown
**
** Returns          TRUE if added OK, else FALSE
**
*******************************************************************************/
extern BOOLEAN BTM_SecAddDevice (BD_ADDR bd_addr, DEV_CLASS dev_class,
                                 BD_NAME bd_name, UINT8 *features,
                                 UINT32 trusted_mask[], LINK_KEY link_key,
                                 UINT8 key_type, tBTM_IO_CAP io_cap, UINT8 pin_length);


/** Free resources associated with the device associated with |bd_addr| address.
 *
 * *** WARNING ***
 * tBTM_SEC_DEV_REC associated with bd_addr becomes invalid after this function
 * is called, also any of it's fields. i.e. if you use p_dev_rec->bd_addr, it is
 * no longer valid!
 * *** WARNING ***
 *
 * Returns true if removed OK, false if not found or ACL link is active.
 */
extern BOOLEAN BTM_SecDeleteDevice (BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_SecClearSecurityFlags
**
** Description      Reset the security flags (mark as not-paired) for a given
**                  remove device.
**
*******************************************************************************/
extern void BTM_SecClearSecurityFlags (BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_SecGetDeviceLinkKey
**
** Description      This function is called to obtain link key for the device
**                  it returns BTM_SUCCESS if link key is available, or
**                  BTM_UNKNOWN_ADDR if Security Manager does not know about
**                  the device or device record does not contain link key info
**
** Returns          BTM_SUCCESS if successful, otherwise error code
**
*******************************************************************************/
extern tBTM_STATUS BTM_SecGetDeviceLinkKey (BD_ADDR bd_addr,
                                            LINK_KEY link_key);


/*******************************************************************************
**
** Function         BTM_SecGetDeviceLinkKeyType
**
** Description      This function is called to obtain link key type for the
**                  device.
**                  it returns BTM_SUCCESS if link key is available, or
**                  BTM_UNKNOWN_ADDR if Security Manager does not know about
**                  the device or device record does not contain link key info
**
** Returns          BTM_LKEY_TYPE_IGNORE if link key is unknown, link type
**                  otherwise.
**
*******************************************************************************/
extern tBTM_LINK_KEY_TYPE BTM_SecGetDeviceLinkKeyType (BD_ADDR bd_addr);


/*******************************************************************************
**
** Function         BTM_PINCodeReply
**
** Description      This function is called after Security Manager submitted
**                  PIN code request to the UI.
**
** Parameters:      bd_addr      - Address of the device for which PIN was requested
**                  res          - result of the operation BTM_SUCCESS if success
**                  pin_len      - length in bytes of the PIN Code
**                  p_pin        - pointer to array with the PIN Code
**                  trusted_mask - bitwise OR of trusted services (array of UINT32)
**
** Returns          void
**
*******************************************************************************/
extern void BTM_PINCodeReply (BD_ADDR bd_addr, UINT8 res, UINT8 pin_len,
                              UINT8 *p_pin, UINT32 trusted_mask[]);


/*******************************************************************************
**
** Function         BTM_SecBond
**
** Description      This function is called to perform bonding with peer device.
**
** Parameters:      bd_addr      - Address of the device to bond
**                  pin_len      - length in bytes of the PIN Code
**                  p_pin        - pointer to array with the PIN Code
**                  trusted_mask - bitwise OR of trusted services (array of UINT32)

** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SecBond (BD_ADDR bd_addr,
                                UINT8 pin_len, UINT8 *p_pin,
                                UINT32 trusted_mask[]);

/*******************************************************************************
**
** Function         BTM_SecBondByTransport
**
** Description      This function is called to perform bonding by designated transport
**
** Parameters:      bd_addr      - Address of the device to bond
**                  pin_len      - length in bytes of the PIN Code
**                  p_pin        - pointer to array with the PIN Code
**                  trusted_mask - bitwise OR of trusted services (array of UINT32)
**                  transport :  Physical transport to use for bonding (BR/EDR or LE)
**
** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SecBondByTransport (BD_ADDR bd_addr,
                                           tBT_TRANSPORT transport,
                                           UINT8 pin_len, UINT8 *p_pin,
                                           UINT32 trusted_mask[]);

/*******************************************************************************
**
** Function         BTM_SecBondCancel
**
** Description      This function is called to cancel ongoing bonding process
**                  with peer device.
**
** Returns          BTM_CMD_STARTED if successfully initiated, otherwise error
**
*******************************************************************************/
extern tBTM_STATUS BTM_SecBondCancel (BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_SetEncryption
**
** Description      This function is called to ensure that connection is
**                  encrypted.  Should be called only on an open connection.
**                  Typically only needed for connections that first want to
**                  bring up unencrypted links, then later encrypt them.
**
** Parameters:      bd_addr       - Address of the peer device
**                  transport     - Link transport
**                  p_callback    - Pointer to callback function called if
**                                  this function returns PENDING after required
**                                  procedures are completed.  Can be set to NULL
**                                  if status is not desired.
**                  p_ref_data    - pointer to any data the caller wishes to receive
**                                  in the callback function upon completion.
**                                  can be set to NULL if not used.
**                  sec_act       - LE security action, unused for BR/EDR
**
** Returns          BTM_SUCCESS   - already encrypted
**                  BTM_PENDING   - command will be returned in the callback
**                  BTM_WRONG_MODE- connection not up.
**                  BTM_BUSY      - security procedures are currently active
**                  BTM_MODE_UNSUPPORTED - if security manager not linked in.
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetEncryption (BD_ADDR bd_addr, tBT_TRANSPORT transport,
                                      tBTM_SEC_CBACK *p_callback,
                                      void *p_ref_data, tBTM_BLE_SEC_ACT sec_act);

/*******************************************************************************
**
** Function         BTM_ConfirmReqReply
**
** Description      This function is called to confirm the numeric value for
**                  Simple Pairing in response to BTM_SP_CFM_REQ_EVT
**
** Parameters:      res           - result of the operation BTM_SUCCESS if success
**                  bd_addr       - Address of the peer device
**
*******************************************************************************/
extern void BTM_ConfirmReqReply(tBTM_STATUS res, BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_PasskeyReqReply
**
** Description      This function is called to provide the passkey for
**                  Simple Pairing in response to BTM_SP_KEY_REQ_EVT
**
** Parameters:      res           - result of the operation BTM_SUCCESS if success
**                  bd_addr       - Address of the peer device
**                  passkey       - numeric value in the range of 0 - 999999(0xF423F).
**
*******************************************************************************/
extern void BTM_PasskeyReqReply(tBTM_STATUS res, BD_ADDR bd_addr, UINT32 passkey);

/*******************************************************************************
**
** Function         BTM_SendKeypressNotif
**
** Description      This function is used during the passkey entry model
**                  by a device with KeyboardOnly IO capabilities
**                  (very likely to be a HID Device).
**                  It is called by a HID Device to inform the remote device when
**                  a key has been entered or erased.
**
** Parameters:      bd_addr - Address of the peer device
**                  type - notification type
**
*******************************************************************************/
extern void BTM_SendKeypressNotif(BD_ADDR bd_addr, tBTM_SP_KEY_TYPE type);

/*******************************************************************************
**
** Function         BTM_IoCapRsp
**
** Description      This function is called in response to BTM_SP_IO_REQ_EVT
**                  When the event data io_req.oob_data is set to BTM_OOB_UNKNOWN
**                  by the tBTM_SP_CALLBACK implementation, this function is
**                  called to provide the actual response
**
** Parameters:      bd_addr - Address of the peer device
**                  io_cap  - The IO capability of local device.
**                  oob     - BTM_OOB_NONE or BTM_OOB_PRESENT.
**                  auth_req- MITM protection required or not.
**
*******************************************************************************/
extern void BTM_IoCapRsp(BD_ADDR bd_addr, tBTM_IO_CAP io_cap,
                         tBTM_OOB_DATA oob, tBTM_AUTH_REQ auth_req);

/*******************************************************************************
**
** Function         BTM_ReadLocalOobData
**
** Description      This function is called to read the local OOB data from
**                  LM
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadLocalOobData(void);

/*******************************************************************************
**
** Function         BTM_RemoteOobDataReply
**
** Description      This function is called to provide the remote OOB data for
**                  Simple Pairing in response to BTM_SP_RMT_OOB_EVT
**
** Parameters:      bd_addr     - Address of the peer device
**                  c           - simple pairing Hash C.
**                  r           - simple pairing Randomizer  C.
**
*******************************************************************************/
extern void BTM_RemoteOobDataReply(tBTM_STATUS res, BD_ADDR bd_addr,
                                   BT_OCTET16 c, BT_OCTET16 r);

/*******************************************************************************
**
** Function         BTM_BuildOobData
**
** Description      This function is called to build the OOB data payload to
**                  be sent over OOB (non-Bluetooth) link
**
** Parameters:      p_data  - the location for OOB data
**                  max_len - p_data size.
**                  c       - simple pairing Hash C.
**                  r       - simple pairing Randomizer  C.
**                  name_len- 0, local device name would not be included.
**                            otherwise, the local device name is included for
**                            up to this specified length
**
** Returns          Number of bytes in p_data.
**
*******************************************************************************/
extern UINT16 BTM_BuildOobData(UINT8 *p_data, UINT16 max_len, BT_OCTET16 c,
                               BT_OCTET16 r, UINT8 name_len);

/*******************************************************************************
**
** Function         BTM_BothEndsSupportSecureConnections
**
** Description      This function is called to check if both the local device and the peer device
**                   specified by bd_addr support BR/EDR Secure Connections.
**
** Parameters:      bd_addr - address of the peer
**
** Returns          TRUE if BR/EDR Secure Connections are supported by both local
**                  and the remote device.
**                  else FALSE.
**
*******************************************************************************/
extern BOOLEAN BTM_BothEndsSupportSecureConnections(BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_PeerSupportsSecureConnections
**
** Description      This function is called to check if the peer supports
**                  BR/EDR Secure Connections.
**
** Parameters:      bd_addr - address of the peer
**
** Returns          TRUE if BR/EDR Secure Connections are supported by the peer,
**                  else FALSE.
**
*******************************************************************************/
extern BOOLEAN BTM_PeerSupportsSecureConnections(BD_ADDR bd_addr);

/*******************************************************************************
**
** Function         BTM_ReadOobData
**
** Description      This function is called to parse the OOB data payload
**                  received over OOB (non-Bluetooth) link
**
** Parameters:      p_data  - the location for OOB data
**                  eir_tag - The associated EIR tag to read the data.
**                  *p_len(output) - the length of the data with the given tag.
**
** Returns          the beginning of the data with the given tag.
**                  NULL, if the tag is not found.
**
*******************************************************************************/
extern UINT8 * BTM_ReadOobData(UINT8 *p_data, UINT8 eir_tag, UINT8 *p_len);

/*******************************************************************************
**
** Function         BTM_SecReadDevName
**
** Description      Looks for the device name in the security database for the
**                  specified BD address.
**
** Returns          Pointer to the name or NULL
**
*******************************************************************************/
extern char *BTM_SecReadDevName (BD_ADDR bd_addr);


/*****************************************************************************
**  POWER MANAGEMENT FUNCTIONS
*****************************************************************************/
/*******************************************************************************
**
** Function         BTM_PmRegister
**
** Description      register or deregister with power manager
**
** Returns          BTM_SUCCESS if successful,
**                  BTM_NO_RESOURCES if no room to hold registration
**                  BTM_ILLEGAL_VALUE
**
*******************************************************************************/
extern tBTM_STATUS BTM_PmRegister (UINT8 mask, UINT8 *p_pm_id,
                                   tBTM_PM_STATUS_CBACK *p_cb);


/*******************************************************************************
**
** Function         BTM_SetPowerMode
**
** Description      store the mode in control block or
**                  alter ACL connection behavior.
**
** Returns          BTM_SUCCESS if successful,
**                  BTM_UNKNOWN_ADDR if bd addr is not active or bad
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetPowerMode (UINT8 pm_id, BD_ADDR remote_bda,
                                     tBTM_PM_PWR_MD *p_mode);


/*******************************************************************************
**
** Function         BTM_ReadPowerMode
**
** Description      This returns the current mode for a specific
**                  ACL connection.
**
** Input Param      remote_bda - device address of desired ACL connection
**
** Output Param     p_mode - address where the current mode is copied into.
**                          BTM_ACL_MODE_NORMAL
**                          BTM_ACL_MODE_HOLD
**                          BTM_ACL_MODE_SNIFF
**                          BTM_ACL_MODE_PARK
**                          (valid only if return code is BTM_SUCCESS)
**
** Returns          BTM_SUCCESS if successful,
**                  BTM_UNKNOWN_ADDR if bd addr is not active or bad
**
*******************************************************************************/
extern tBTM_STATUS BTM_ReadPowerMode (BD_ADDR remote_bda,
                                      tBTM_PM_MODE *p_mode);

/*******************************************************************************
**
** Function         BTM_SetSsrParams
**
** Description      This sends the given SSR parameters for the given ACL
**                  connection if it is in ACTIVE mode.
**
** Input Param      remote_bda - device address of desired ACL connection
**                  max_lat    - maximum latency (in 0.625ms)(0-0xFFFE)
**                  min_rmt_to - minimum remote timeout
**                  min_loc_to - minimum local timeout
**
**
** Returns          BTM_SUCCESS if the HCI command is issued successful,
**                  BTM_UNKNOWN_ADDR if bd addr is not active or bad
**                  BTM_CMD_STORED if the command is stored
**
*******************************************************************************/
extern tBTM_STATUS BTM_SetSsrParams (BD_ADDR remote_bda, UINT16 max_lat,
                                     UINT16 min_rmt_to, UINT16 min_loc_to);

/*******************************************************************************
**
** Function         BTM_GetHCIConnHandle
**
** Description      This function is called to get the handle for an ACL connection
**                  to a specific remote BD Address.
**
** Returns          the handle of the connection, or 0xFFFF if none.
**
*******************************************************************************/
extern UINT16 BTM_GetHCIConnHandle (const BD_ADDR remote_bda, tBT_TRANSPORT transport);

/*******************************************************************************
**
** Function         BTM_DeleteStoredLinkKey
**
** Description      This function is called to delete link key for the specified
**                  device addresses from the NVRAM storage attached to the Bluetooth
**                  controller.
**
** Parameters:      bd_addr      - Addresses of the devices
**                  p_cb         - Call back function to be called to return
**                                 the results
**
*******************************************************************************/
extern tBTM_STATUS BTM_DeleteStoredLinkKey(BD_ADDR bd_addr, tBTM_CMPL_CB *p_cb);

/*******************************************************************************
**
** Function         BTM_WriteEIR
**
** Description      This function is called to write EIR data to controller.
**
** Parameters       p_buff - allocated HCI command buffer including extended
**                           inquriry response
**
** Returns          BTM_SUCCESS  - if successful
**                  BTM_MODE_UNSUPPORTED - if local device cannot support it
**
*******************************************************************************/
extern tBTM_STATUS BTM_WriteEIR( BT_HDR * p_buff );

/*******************************************************************************
**
** Function         BTM_CheckEirData
**
** Description      This function is called to get EIR data from significant part.
**
** Parameters       p_eir - pointer of EIR significant part
**                  type   - finding EIR data type
**                  p_length - return the length of EIR data
**
** Returns          pointer of EIR data
**
*******************************************************************************/
extern UINT8 *BTM_CheckEirData( UINT8 *p_eir, UINT8 type, UINT8 *p_length );

/*******************************************************************************
**
** Function         BTM_HasEirService
**
** Description      This function is called to know if UUID in bit map of UUID.
**
** Parameters       p_eir_uuid - bit map of UUID list
**                  uuid16 - UUID 16-bit
**
** Returns          TRUE - if found
**                  FALSE - if not found
**
*******************************************************************************/
extern BOOLEAN BTM_HasEirService( UINT32 *p_eir_uuid, UINT16 uuid16 );

/*******************************************************************************
**
** Function         BTM_HasInquiryEirService
**
** Description      This function is called to know if UUID in bit map of UUID list.
**
** Parameters       p_results - inquiry results
**                  uuid16 - UUID 16-bit
**
** Returns          BTM_EIR_FOUND - if found
**                  BTM_EIR_NOT_FOUND - if not found and it is complete list
**                  BTM_EIR_UNKNOWN - if not found and it is not complete list
**
*******************************************************************************/
extern tBTM_EIR_SEARCH_RESULT BTM_HasInquiryEirService( tBTM_INQ_RESULTS *p_results,
                                                        UINT16 uuid16 );

/*******************************************************************************
**
** Function         BTM_AddEirService
**
** Description      This function is called to add a service in bit map of UUID list.
**
** Parameters       p_eir_uuid - bit mask of UUID list for EIR
**                  uuid16 - UUID 16-bit
**
** Returns          None
**
*******************************************************************************/
extern void BTM_AddEirService( UINT32 *p_eir_uuid, UINT16 uuid16 );

/*******************************************************************************
**
** Function         BTM_RemoveEirService
**
** Description      This function is called to remove a service in bit map of UUID list.
**
** Parameters       p_eir_uuid - bit mask of UUID list for EIR
**                  uuid16 - UUID 16-bit
**
** Returns          None
**
*******************************************************************************/
extern void BTM_RemoveEirService( UINT32 *p_eir_uuid, UINT16 uuid16 );

/*******************************************************************************
**
** Function         BTM_GetEirSupportedServices
**
** Description      This function is called to get UUID list from bit map of UUID list.
**
** Parameters       p_eir_uuid - bit mask of UUID list for EIR
**                  p - reference of current pointer of EIR
**                  max_num_uuid16 - max number of UUID can be written in EIR
**                  num_uuid16 - number of UUID have been written in EIR
**
** Returns          BTM_EIR_MORE_16BITS_UUID_TYPE, if it has more than max
**                  BTM_EIR_COMPLETE_16BITS_UUID_TYPE, otherwise
**
*******************************************************************************/
extern UINT8 BTM_GetEirSupportedServices( UINT32 *p_eir_uuid,    UINT8 **p,
                                          UINT8  max_num_uuid16, UINT8 *p_num_uuid16);

/*******************************************************************************
**
** Function         BTM_GetEirUuidList
**
** Description      This function parses EIR and returns UUID list.
**
** Parameters       p_eir - EIR
**                  uuid_size - LEN_UUID_16, LEN_UUID_32, LEN_UUID_128
**                  p_num_uuid - return number of UUID in found list
**                  p_uuid_list - return UUID 16-bit list
**                  max_num_uuid - maximum number of UUID to be returned
**
** Returns          0 - if not found
**                  BTM_EIR_COMPLETE_16BITS_UUID_TYPE
**                  BTM_EIR_MORE_16BITS_UUID_TYPE
**                  BTM_EIR_COMPLETE_32BITS_UUID_TYPE
**                  BTM_EIR_MORE_32BITS_UUID_TYPE
**                  BTM_EIR_COMPLETE_128BITS_UUID_TYPE
**                  BTM_EIR_MORE_128BITS_UUID_TYPE
**
*******************************************************************************/
extern UINT8 BTM_GetEirUuidList( UINT8 *p_eir, UINT8 uuid_size, UINT8 *p_num_uuid,
                                 UINT8 *p_uuid_list, UINT8 max_num_uuid);

/*****************************************************************************
**  SCO OVER HCI
*****************************************************************************/
/*******************************************************************************
**
** Function         BTM_ConfigScoPath
**
** Description      This function enable/disable SCO over HCI and registers SCO
**                  data callback if SCO over HCI is enabled.
**
** Parameter        path: SCO or HCI
**                  p_sco_data_cb: callback function or SCO data if path is set
**                                 to transport.
**                  p_pcm_param: pointer to the PCM interface parameter. If a NULL
**                               pointer is used, PCM parameter maintained in
**                               the control block will be used; otherwise update
**                               control block value.
**                  err_data_rpt: Lisbon feature to enable the erronous data report
**                                or not.
**
** Returns          BTM_SUCCESS if the successful.
**                  BTM_NO_RESOURCES: no rsource to start the command.
**                  BTM_ILLEGAL_VALUE: invalid callback function pointer.
**                  BTM_CMD_STARTED :Command sent. Waiting for command cmpl event.
**
**
*******************************************************************************/
extern tBTM_STATUS BTM_ConfigScoPath (tBTM_SCO_ROUTE_TYPE path,
                                      tBTM_SCO_DATA_CB *p_sco_data_cb,
                                      tBTM_SCO_PCM_PARAM *p_pcm_param,
                                      BOOLEAN err_data_rpt);

/*******************************************************************************
**
** Function         BTM_WriteScoData
**
** Description      This function write SCO data to a specified instance. The data
**                  to be written p_buf needs to carry an offset of
**                  HCI_SCO_PREAMBLE_SIZE bytes, and the data length can not
**                  exceed BTM_SCO_DATA_SIZE_MAX bytes, whose default value is set
**                  to 60 and is configurable. Data longer than the maximum bytes
**                  will be truncated.
**
** Returns          BTM_SUCCESS: data write is successful
**                  BTM_ILLEGAL_VALUE: SCO data contains illegal offset value.
**                  BTM_SCO_BAD_LENGTH: SCO data length exceeds the max SCO packet
**                                      size.
**                  BTM_NO_RESOURCES: no resources.
**                  BTM_UNKNOWN_ADDR: unknown SCO connection handle, or SCO is not
**                                    routed via HCI.
**
**
*******************************************************************************/
extern tBTM_STATUS BTM_WriteScoData (UINT16 sco_inx, BT_HDR *p_buf);

/*******************************************************************************
**
** Function         BTM_SetARCMode
**
** Description      Send Audio Routing Control command.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_SetARCMode (UINT8 iface, UINT8 arc_mode, tBTM_VSC_CMPL_CB *p_arc_cb);


/*******************************************************************************
**
** Function         BTM_PCM2Setup_Write
**
** Description      Send PCM2_Setup write command.
**
** Returns          void
**
*******************************************************************************/
extern void BTM_PCM2Setup_Write (BOOLEAN clk_master, tBTM_VSC_CMPL_CB *p_arc_cb);


/*******************************************************************************
**
** Function         BTM_PM_ReadControllerState
**
** Description      This function is called to obtain the controller state
**
** Returns          Controller state (BTM_CONTRL_ACTIVE, BTM_CONTRL_SCAN, and BTM_CONTRL_IDLE)
**
*******************************************************************************/
extern tBTM_CONTRL_STATE BTM_PM_ReadControllerState(void);

#ifdef __cplusplus
}
#endif

#endif /* BTM_API_H */
