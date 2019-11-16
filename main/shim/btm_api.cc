/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "bt_shim_btm"

#include <base/callback.h>

#include "main/shim/btm.h"
#include "main/shim/btm_api.h"
#include "osi/include/log.h"
#include "stack/btm/btm_int_types.h"

static bluetooth::shim::Btm shim_btm;

/*******************************************************************************
 *
 * Function         BTM_StartInquiry
 *
 * Description      This function is called to start an inquiry.
 *
 * Parameters:      p_inqparms - pointer to the inquiry information
 *                      mode - GENERAL or LIMITED inquiry, BR/LE bit mask
 *                             seperately
 *                      duration - length in 1.28 sec intervals (If '0', the
 *                                 inquiry is CANCELLED)
 *                      max_resps - maximum amount of devices to search for
 *                                  before ending the inquiry
 *                      filter_cond_type - BTM_CLR_INQUIRY_FILTER,
 *                                         BTM_FILTER_COND_DEVICE_CLASS, or
 *                                         BTM_FILTER_COND_BD_ADDR
 *                      filter_cond - value for the filter (based on
 *                                                          filter_cond_type)
 *
 *                  p_results_cb   - Pointer to the callback routine which gets
 *                                called upon receipt of an inquiry result. If
 *                                this field is NULL, the application is not
 *                                notified.
 *
 *                  p_cmpl_cb   - Pointer to the callback routine which gets
 *                                called upon completion.  If this field is
 *                                NULL, the application is not notified when
 *                                completed.
 * Returns          tBTM_STATUS
 *                  BTM_CMD_STARTED if successfully initiated
 *                  BTM_BUSY if already in progress
 *                  BTM_ILLEGAL_VALUE if parameter(s) are out of range
 *                  BTM_NO_RESOURCES if could not allocate resources to start
 *                                   the command
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_StartInquiry(tBTM_INQ_PARMS* p_inqparms,
                                              tBTM_INQ_RESULTS_CB* p_results_cb,
                                              tBTM_CMPL_CB* p_cmpl_cb) {
  CHECK(p_inqparms != nullptr);
  CHECK(p_results_cb != nullptr);
  CHECK(p_cmpl_cb != nullptr);

  uint8_t classic_mode = p_inqparms->mode & 0x0f;
  // TODO(cmanton) Setup the LE portion too
  uint8_t le_mode = p_inqparms->mode >> 4;

  LOG_INFO(LOG_TAG, "%s Start inquiry mode classic:%hhd le:%hhd", __func__,
           classic_mode, le_mode);

  if (!shim_btm.SetInquiryFilter(classic_mode, p_inqparms->filter_cond_type,
                                 p_inqparms->filter_cond)) {
    LOG_WARN(LOG_TAG, "%s Unable to set inquiry filter", __func__);
    return BTM_ERR_PROCESSING;
  }

  if (!shim_btm.StartInquiry(classic_mode, p_inqparms->duration,
                             p_inqparms->max_resps)) {
    LOG_WARN(LOG_TAG, "%s Unable to start inquiry", __func__);
    return BTM_ERR_PROCESSING;
  }
  return BTM_CMD_STARTED;
}

/*******************************************************************************
 *
 * Function         BTM_SetPeriodicInquiryMode
 *
 * Description      This function is called to set the device periodic inquiry
 *                  mode. If the duration is zero, the periodic inquiry mode is
 *                  cancelled.
 *
 *                  Note: We currently do not allow concurrent inquiry and
 *                  periodic inquiry.
 *
 * Parameters:      p_inqparms - pointer to the inquiry information
 *                      mode - GENERAL or LIMITED inquiry
 *                      duration - length in 1.28 sec intervals (If '0', the
 *                                 inquiry is CANCELLED)
 *                      max_resps - maximum amount of devices to search for
 *                                  before ending the inquiry
 *                      filter_cond_type - BTM_CLR_INQUIRY_FILTER,
 *                                         BTM_FILTER_COND_DEVICE_CLASS, or
 *                                         BTM_FILTER_COND_BD_ADDR
 *                      filter_cond - value for the filter (based on
 *                                                          filter_cond_type)
 *
 *                  max_delay - maximum amount of time between successive
 *                              inquiries
 *                  min_delay - minimum amount of time between successive
 *                              inquiries
 *                  p_results_cb - callback returning pointer to results
 *                              (tBTM_INQ_RESULTS)
 *
 * Returns          BTM_CMD_STARTED if successfully started
 *                  BTM_ILLEGAL_VALUE if a bad parameter is detected
 *                  BTM_NO_RESOURCES if could not allocate a message buffer
 *                  BTM_SUCCESS - if cancelling the periodic inquiry
 *                  BTM_BUSY - if an inquiry is already active
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_SetPeriodicInquiryMode(
    tBTM_INQ_PARMS* p_inqparms, uint16_t max_delay, uint16_t min_delay,
    tBTM_INQ_RESULTS_CB* p_results_cb) {
  CHECK(p_inqparms != nullptr);
  CHECK(p_results_cb != nullptr);

  if (p_inqparms->duration < BTM_MIN_INQUIRY_LEN ||
      p_inqparms->duration > BTM_MAX_INQUIRY_LENGTH ||
      min_delay <= p_inqparms->duration ||
      min_delay < BTM_PER_INQ_MIN_MIN_PERIOD ||
      min_delay > BTM_PER_INQ_MAX_MIN_PERIOD || max_delay <= min_delay ||
      max_delay < BTM_PER_INQ_MIN_MAX_PERIOD) {
    return (BTM_ILLEGAL_VALUE);
  }

  if (shim_btm.IsInquiryActive()) {
    return BTM_BUSY;
  }

  switch (p_inqparms->filter_cond_type) {
    case kClearInquiryFilter:
      shim_btm.ClearInquiryFilter();
      return BTM_SUCCESS;
      break;
    case kFilterOnDeviceClass:
      shim_btm.SetFilterInquiryOnDevice();
      return BTM_SUCCESS;
      break;
    case kFilterOnAddress:
      shim_btm.SetFilterInquiryOnAddress();
      return BTM_SUCCESS;
      break;
    default:
      return BTM_ILLEGAL_VALUE;
  }
  return BTM_MODE_UNSUPPORTED;
}

/*******************************************************************************
 *
 * Function         BTM_SetDiscoverability
 *
 * Description      This function is called to set the device into or out of
 *                  discoverable mode. Discoverable mode means inquiry
 *                  scans are enabled.  If a value of '0' is entered for window
 *                  or interval, the default values are used.
 *
 * Returns          BTM_SUCCESS if successful
 *                  BTM_BUSY if a setting of the filter is already in progress
 *                  BTM_NO_RESOURCES if couldn't get a memory pool buffer
 *                  BTM_ILLEGAL_VALUE if a bad parameter was detected
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_SetDiscoverability(uint16_t discoverable_mode,
                                                    uint16_t window,
                                                    uint16_t interval) {
  uint16_t classic_discoverable_mode = discoverable_mode & 0xff;
  uint16_t le_discoverable_mode = discoverable_mode >> 8;

  if (window == 0) window = BTM_DEFAULT_DISC_WINDOW;
  if (interval == 0) interval = BTM_DEFAULT_DISC_INTERVAL;

  switch (le_discoverable_mode) {
    case kDiscoverableModeOff:
      shim_btm.SetLeDiscoverabilityOff();
      break;
    case kLimitedDiscoverableMode:
      shim_btm.SetLeLimitedDiscoverability();
      break;
    case kGeneralDiscoverableMode:
      shim_btm.SetLeGeneralDiscoverability();
      break;
  }

  switch (classic_discoverable_mode) {
    case kDiscoverableModeOff:
      shim_btm.SetClassicDiscoverabilityOff();
      break;
    case kLimitedDiscoverableMode:
      shim_btm.SetClassicLimitedDiscoverability(window, interval);
      break;
    case kGeneralDiscoverableMode:
      shim_btm.SetClassicGeneralDiscoverability(window, interval);
      break;
  }

  return BTM_SUCCESS;
}

/*******************************************************************************
 *
 * Function         BTM_SetInquiryScanType
 *
 * Description      This function is called to set the iquiry scan-type to
 *                  standard or interlaced.
 *
 * Returns          BTM_SUCCESS if successful
 *                  BTM_MODE_UNSUPPORTED if not a 1.2 device
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_SetInquiryScanType(uint16_t scan_type) {
  switch (scan_type) {
    case kInterlacedScanType:
      shim_btm.SetInterlacedInquiryScan();
      return BTM_SUCCESS;
      break;
    case kStandardScanType:
      shim_btm.SetStandardInquiryScan();
      return BTM_SUCCESS;
      break;
    default:
      return BTM_ILLEGAL_VALUE;
  }
  return BTM_WRONG_MODE;
}

/*******************************************************************************
 *
 * Function         BTM_SetPageScanType
 *
 * Description      This function is called to set the page scan-type to
 *                  standard or interlaced.
 *
 * Returns          BTM_SUCCESS if successful
 *                  BTM_MODE_UNSUPPORTED if not a 1.2 device
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_SetPageScanType(uint16_t scan_type) {
  switch (scan_type) {
    case kInterlacedScanType:
      if (!shim_btm.IsInterlacedScanSupported()) {
        return BTM_MODE_UNSUPPORTED;
      }
      shim_btm.SetInterlacedPageScan();
      return BTM_SUCCESS;
      break;
    case kStandardScanType:
      shim_btm.SetStandardPageScan();
      return BTM_SUCCESS;
      break;
    default:
      return BTM_ILLEGAL_VALUE;
  }
  return BTM_WRONG_MODE;
}

/*******************************************************************************
 *
 * Function         BTM_SetInquiryMode
 *
 * Description      This function is called to set standard or with RSSI
 *                  mode of the inquiry for local device.
 *
 * Output Params:   mode - standard, with RSSI, extended
 *
 * Returns          BTM_SUCCESS if successful
 *                  BTM_NO_RESOURCES if couldn't get a memory pool buffer
 *                  BTM_ILLEGAL_VALUE if a bad parameter was detected
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_SetInquiryMode(uint8_t inquiry_mode) {
  switch (inquiry_mode) {
    case kStandardInquiryResult:
      if (shim_btm.SetStandardInquiryResultMode()) {
        return BTM_SUCCESS;
      }
      break;
    case kInquiryResultWithRssi:
      if (shim_btm.SetInquiryWithRssiResultMode()) {
        return BTM_SUCCESS;
      }
      break;
    case kExtendedInquiryResult:
      if (shim_btm.SetExtendedInquiryResultMode()) {
        return BTM_SUCCESS;
      }
      break;
    default:
      return BTM_ILLEGAL_VALUE;
  }
  return BTM_MODE_UNSUPPORTED;
}

/*******************************************************************************
 *
 * Function         BTM_ReadDiscoverability
 *
 * Description      This function is called to read the current discoverability
 *                  mode of the device.
 *
 * Output Params:   p_window - current inquiry scan duration
 *                  p_interval - current inquiry scan interval
 *
 * Returns          BTM_NON_DISCOVERABLE, BTM_LIMITED_DISCOVERABLE, or
 *                  BTM_GENERAL_DISCOVERABLE
 *
 ******************************************************************************/
uint16_t bluetooth::shim::BTM_ReadDiscoverability(uint16_t* p_window,
                                                  uint16_t* p_interval) {
  DiscoverabilityState state = shim_btm.GetClassicDiscoverabilityState();

  if (p_interval) *p_interval = state.interval;
  if (p_window) *p_window = state.window;

  return state.mode;
}

/*******************************************************************************
 *
 * Function         BTM_CancelPeriodicInquiry
 *
 * Description      This function cancels a periodic inquiry
 *
 * Returns
 *                  BTM_NO_RESOURCES if could not allocate a message buffer
 *                  BTM_SUCCESS - if cancelling the periodic inquiry
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_CancelPeriodicInquiry(void) {
  shim_btm.CancelPeriodicInquiry();
  return BTM_SUCCESS;
}

/*******************************************************************************
 *
 * Function         BTM_SetConnectability
 *
 * Description      This function is called to set the device into or out of
 *                  connectable mode. Discoverable mode means page scans are
 *                  enabled.
 *
 * Returns          BTM_SUCCESS if successful
 *                  BTM_ILLEGAL_VALUE if a bad parameter is detected
 *                  BTM_NO_RESOURCES if could not allocate a message buffer
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_SetConnectability(uint16_t page_mode,
                                                   uint16_t window,
                                                   uint16_t interval) {
  uint16_t classic_connectible_mode = page_mode & 0xff;
  uint16_t le_connectible_mode = page_mode >> 8;

  if (!window) window = BTM_DEFAULT_CONN_WINDOW;
  if (!interval) interval = BTM_DEFAULT_CONN_INTERVAL;

  switch (le_connectible_mode) {
    case kConnectibleModeOff:
      shim_btm.SetLeConnectibleOff();
      break;
    case kConnectibleModeOn:
      shim_btm.SetLeConnectibleOn();
      break;
    default:
      return BTM_ILLEGAL_VALUE;
      break;
  }

  switch (classic_connectible_mode) {
    case kConnectibleModeOff:
      shim_btm.SetClassicConnectibleOff();
      break;
    case kConnectibleModeOn:
      shim_btm.SetClassicConnectibleOn();
      break;
    default:
      return BTM_ILLEGAL_VALUE;
      break;
  }
  return BTM_SUCCESS;
}

/*******************************************************************************
 *
 * Function         BTM_ReadConnectability
 *
 * Description      This function is called to read the current discoverability
 *                  mode of the device.
 * Output Params    p_window - current page scan duration
 *                  p_interval - current time between page scans
 *
 * Returns          BTM_NON_CONNECTABLE or BTM_CONNECTABLE
 *
 ******************************************************************************/
uint16_t bluetooth::shim::BTM_ReadConnectability(uint16_t* p_window,
                                                 uint16_t* p_interval) {
  ConnectabilityState state = shim_btm.GetClassicConnectabilityState();

  if (p_window) *p_window = state.window;
  if (p_interval) *p_interval = state.interval;

  return state.mode;
}

/*******************************************************************************
 *
 * Function         BTM_IsInquiryActive
 *
 * Description      This function returns a bit mask of the current inquiry
 *                  state
 *
 * Returns          BTM_INQUIRY_INACTIVE if inactive (0)
 *                  BTM_LIMITED_INQUIRY_ACTIVE if a limted inquiry is active
 *                  BTM_GENERAL_INQUIRY_ACTIVE if a general inquiry is active
 *                  BTM_PERIODIC_INQUIRY_ACTIVE if a periodic inquiry is active
 *
 ******************************************************************************/
uint16_t bluetooth::shim::BTM_IsInquiryActive(void) {
  if (shim_btm.IsLimitedInquiryActive()) {
    return BTM_LIMITED_INQUIRY_ACTIVE;
  } else if (shim_btm.IsGeneralInquiryActive()) {
    return BTM_GENERAL_INQUIRY_ACTIVE;
  } else if (shim_btm.IsGeneralPeriodicInquiryActive() ||
             shim_btm.IsLimitedPeriodicInquiryActive()) {
    return BTM_PERIODIC_INQUIRY_ACTIVE;
  }
  return BTM_INQUIRY_INACTIVE;
}

/*******************************************************************************
 *
 * Function         BTM_CancelInquiry
 *
 * Description      This function cancels an inquiry if active
 *
 * Returns          BTM_SUCCESS if successful
 *                  BTM_NO_RESOURCES if could not allocate a message buffer
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_CancelInquiry(void) {
  shim_btm.CancelInquiry();
  return BTM_SUCCESS;
}

/*******************************************************************************
 *
 * Function         BTM_ReadRemoteDeviceName
 *
 * Description      This function initiates a remote device HCI command to the
 *                  controller and calls the callback when the process has
 *                  completed.
 *
 * Input Params:    remote_bda      - device address of name to retrieve
 *                  p_cb            - callback function called when
 *                                    BTM_CMD_STARTED is returned.
 *                                    A pointer to tBTM_REMOTE_DEV_NAME is
 *                                    passed to the callback.
 *
 * Returns
 *                  BTM_CMD_STARTED is returned if the request was successfully
 *                                  sent to HCI.
 *                  BTM_BUSY if already in progress
 *                  BTM_UNKNOWN_ADDR if device address is bad
 *                  BTM_NO_RESOURCES if could not allocate resources to start
 *                                   the command
 *                  BTM_WRONG_MODE if the device is not up.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_ReadRemoteDeviceName(
    const RawAddress& raw_address, tBTM_CMPL_CB* callback,
    tBT_TRANSPORT transport) {
  CHECK(callback != nullptr);
  tBTM_STATUS status = BTM_NO_RESOURCES;

  switch (transport) {
    case BT_TRANSPORT_LE:
      status = shim_btm.ReadLeRemoteDeviceName(raw_address, callback);
      break;
    case BT_TRANSPORT_BR_EDR:
      status = shim_btm.ReadClassicRemoteDeviceName(raw_address, callback);
      break;
    default:
      LOG_WARN(LOG_TAG, "%s Unspecified transport:%d", __func__, transport);
      break;
  }
  return status;
}

/*******************************************************************************
 *
 * Function         BTM_CancelRemoteDeviceName
 *
 * Description      This function initiates the cancel request for the specified
 *                  remote device.
 *
 * Input Params:    None
 *
 * Returns
 *                  BTM_CMD_STARTED is returned if the request was successfully
 *                                  sent to HCI.
 *                  BTM_NO_RESOURCES if could not allocate resources to start
 *                                   the command
 *                  BTM_WRONG_MODE if there is not an active remote name
 *                                 request.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_CancelRemoteDeviceName(void) {
  return shim_btm.CancelAllReadRemoteDeviceName();
}

/*******************************************************************************
 *
 * Function         BTM_InqDbRead
 *
 * Description      This function looks through the inquiry database for a match
 *                  based on Bluetooth Device Address. This is the application's
 *                  interface to get the inquiry details of a specific BD
 *                  address.
 *
 * Returns          pointer to entry, or NULL if not found
 *
 ******************************************************************************/
tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbRead(const RawAddress& p_bda) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return nullptr;
}

/*******************************************************************************
 *
 * Function         BTM_InqDbFirst
 *
 * Description      This function looks through the inquiry database for the
 *                  first used entry, and returns that. This is used in
 *                  conjunction with
 *                  BTM_InqDbNext by applications as a way to walk through the
 *                  inquiry database.
 *
 * Returns          pointer to first in-use entry, or NULL if DB is empty
 *
 ******************************************************************************/
tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbFirst(void) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return nullptr;
}

/*******************************************************************************
 *
 * Function         BTM_InqDbNext
 *
 * Description      This function looks through the inquiry database for the
 *                  next used entry, and returns that.  If the input parameter
 *                  is NULL, the first entry is returned.
 *
 * Returns          pointer to next in-use entry, or NULL if no more found.
 *
 ******************************************************************************/
tBTM_INQ_INFO* bluetooth::shim::BTM_InqDbNext(tBTM_INQ_INFO* p_cur) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_cur != nullptr);
  return nullptr;
}

/*******************************************************************************
 *
 * Function         BTM_ClearInqDb
 *
 * Description      This function is called to clear out a device or all devices
 *                  from the inquiry database.
 *
 * Parameter        p_bda - (input) BD_ADDR ->  Address of device to clear
 *                                              (NULL clears all entries)
 *
 * Returns          BTM_BUSY if an inquiry, get remote name, or event filter
 *                          is active, otherwise BTM_SUCCESS
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_ClearInqDb(const RawAddress* p_bda) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  if (p_bda == nullptr) {
    // clear all entries
  } else {
    // clear specific entry
  }
  return BTM_NO_RESOURCES;
}

/*******************************************************************************
 *
 * Function         BTM_ReadInquiryRspTxPower
 *
 * Description      This command will read the inquiry Transmit Power level used
 *                  to transmit the FHS and EIR data packets. This can be used
 *                  directly in the Tx Power Level EIR data type.
 *
 * Returns          BTM_SUCCESS if successful
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_ReadInquiryRspTxPower(tBTM_CMPL_CB* p_cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_cb != nullptr);
  return BTM_NO_RESOURCES;
}

/*******************************************************************************
 *
 * Function         BTM_WriteEIR
 *
 * Description      This function is called to write EIR data to controller.
 *
 * Parameters       p_buff - allocated HCI command buffer including extended
 *                           inquriry response
 *
 * Returns          BTM_SUCCESS  - if successful
 *                  BTM_MODE_UNSUPPORTED - if local device cannot support it
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_WriteEIR(BT_HDR* p_buff) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_buff != nullptr);
  return BTM_NO_RESOURCES;
}

/*******************************************************************************
 *
 * Function         BTM_HasEirService
 *
 * Description      This function is called to know if UUID in bit map of UUID.
 *
 * Parameters       p_eir_uuid - bit map of UUID list
 *                  uuid16 - UUID 16-bit
 *
 * Returns          true - if found
 *                  false - if not found
 *
 ******************************************************************************/
bool bluetooth::shim::BTM_HasEirService(const uint32_t* p_eir_uuid,
                                        uint16_t uuid16) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
  return false;
}

/*******************************************************************************
 *
 * Function         BTM_HasInquiryEirService
 *
 * Description      This function is called to know if UUID in bit map of UUID
 *                  list.
 *
 * Parameters       p_results - inquiry results
 *                  uuid16 - UUID 16-bit
 *
 * Returns          BTM_EIR_FOUND - if found
 *                  BTM_EIR_NOT_FOUND - if not found and it is complete list
 *                  BTM_EIR_UNKNOWN - if not found and it is not complete list
 *
 ******************************************************************************/
tBTM_EIR_SEARCH_RESULT bluetooth::shim::BTM_HasInquiryEirService(
    tBTM_INQ_RESULTS* p_results, uint16_t uuid16) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_results != nullptr);
  return BTM_EIR_UNKNOWN;
}

/*******************************************************************************
 *
 * Function         BTM_AddEirService
 *
 * Description      This function is called to add a service in bit map of UUID
 *                  list.
 *
 * Parameters       p_eir_uuid - bit mask of UUID list for EIR
 *                  uuid16 - UUID 16-bit
 *
 * Returns          None
 *
 ******************************************************************************/
void bluetooth::shim::BTM_AddEirService(uint32_t* p_eir_uuid, uint16_t uuid16) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
}

/*******************************************************************************
 *
 * Function         BTM_RemoveEirService
 *
 * Description      This function is called to remove a service in bit map of
 *                  UUID list.
 *
 * Parameters       p_eir_uuid - bit mask of UUID list for EIR
 *                  uuid16 - UUID 16-bit
 *
 * Returns          None
 *
 ******************************************************************************/
void bluetooth::shim::BTM_RemoveEirService(uint32_t* p_eir_uuid,
                                           uint16_t uuid16) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
}

/*******************************************************************************
 *
 * Function         BTM_GetEirSupportedServices
 *
 * Description      This function is called to get UUID list from bit map of
 *                  UUID list.
 *
 * Parameters       p_eir_uuid - bit mask of UUID list for EIR
 *                  p - reference of current pointer of EIR
 *                  max_num_uuid16 - max number of UUID can be written in EIR
 *                  num_uuid16 - number of UUID have been written in EIR
 *
 * Returns          BTM_EIR_MORE_16BITS_UUID_TYPE, if it has more than max
 *                  BTM_EIR_COMPLETE_16BITS_UUID_TYPE, otherwise
 *
 ******************************************************************************/
uint8_t bluetooth::shim::BTM_GetEirSupportedServices(uint32_t* p_eir_uuid,
                                                     uint8_t** p,
                                                     uint8_t max_num_uuid16,
                                                     uint8_t* p_num_uuid16) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_eir_uuid != nullptr);
  CHECK(p != nullptr);
  CHECK(*p != nullptr);
  CHECK(p_num_uuid16 != nullptr);
  return BTM_NO_RESOURCES;
}

/*******************************************************************************
 *
 * Function         BTM_GetEirUuidList
 *
 * Description      This function parses EIR and returns UUID list.
 *
 * Parameters       p_eir - EIR
 *                  eir_len - EIR len
 *                  uuid_size - Uuid::kNumBytes16, Uuid::kNumBytes32,
 *                              Uuid::kNumBytes128
 *                  p_num_uuid - return number of UUID in found list
 *                  p_uuid_list - return UUID list
 *                  max_num_uuid - maximum number of UUID to be returned
 *
 * Returns          0 - if not found
 *                  BTM_EIR_COMPLETE_16BITS_UUID_TYPE
 *                  BTM_EIR_MORE_16BITS_UUID_TYPE
 *                  BTM_EIR_COMPLETE_32BITS_UUID_TYPE
 *                  BTM_EIR_MORE_32BITS_UUID_TYPE
 *                  BTM_EIR_COMPLETE_128BITS_UUID_TYPE
 *                  BTM_EIR_MORE_128BITS_UUID_TYPE
 *
 ******************************************************************************/
uint8_t bluetooth::shim::BTM_GetEirUuidList(uint8_t* p_eir, size_t eir_len,
                                            uint8_t uuid_size,
                                            uint8_t* p_num_uuid,
                                            uint8_t* p_uuid_list,
                                            uint8_t max_num_uuid) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_eir != nullptr);
  CHECK(p_num_uuid != nullptr);
  CHECK(p_uuid_list != nullptr);
  return 0;
}

/**
 *
 * BLE API HERE
 *
 */

bool bluetooth::shim::BTM_SecAddBleDevice(const RawAddress& bd_addr,
                                          BD_NAME bd_name,
                                          tBT_DEVICE_TYPE dev_type,
                                          tBLE_ADDR_TYPE addr_type) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
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
bool bluetooth::shim::BTM_SecAddBleKey(const RawAddress& bd_addr,
                                       tBTM_LE_KEY_VALUE* p_le_key,
                                       tBTM_LE_KEY_TYPE key_type) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_le_key != nullptr);
  return false;
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
void bluetooth::shim::BTM_BleLoadLocalKeys(uint8_t key_type,
                                           tBTM_BLE_LOCAL_KEYS* p_key) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_key != nullptr);
}

static Octet16 bogus_root;

/** Returns local device encryption root (ER) */
const Octet16& bluetooth::shim::BTM_GetDeviceEncRoot() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return bogus_root;
}

/** Returns local device identity root (IR). */
const Octet16& bluetooth::shim::BTM_GetDeviceIDRoot() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return bogus_root;
}

/** Return local device DHK. */
const Octet16& bluetooth::shim::BTM_GetDeviceDHK() {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return bogus_root;
}

/*******************************************************************************
 *
 * Function         BTM_ReadConnectionAddr
 *
 * Description      This function is called to get the local device address
 *                  information.
 *
 * Returns          void
 *
 ******************************************************************************/
void bluetooth::shim::BTM_ReadConnectionAddr(const RawAddress& remote_bda,
                                             RawAddress& local_conn_addr,
                                             tBLE_ADDR_TYPE* p_addr_type) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_addr_type != nullptr);
}

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
bool bluetooth::shim::BTM_IsBleConnection(uint16_t conn_handle) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

/*******************************************************************************
 *
 * Function       BTM_ReadRemoteConnectionAddr
 *
 * Description    This function is read the remote device address currently used
 *
 * Parameters     pseudo_addr: pseudo random address available
 *                conn_addr:connection address used
 *                p_addr_type : BD Address type, Public or Random of the address
 *                              used
 *
 * Returns        bool, true if connection to remote device exists, else false
 *
 ******************************************************************************/
bool bluetooth::shim::BTM_ReadRemoteConnectionAddr(
    const RawAddress& pseudo_addr, RawAddress& conn_addr,
    tBLE_ADDR_TYPE* p_addr_type) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_addr_type != nullptr);
  return false;
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
void bluetooth::shim::BTM_SecurityGrant(const RawAddress& bd_addr,
                                        uint8_t res) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
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
 *                  trusted_mask - bitwise OR of trusted services (array of
 *                                 uint32_t)
 *
 ******************************************************************************/
void bluetooth::shim::BTM_BlePasskeyReply(const RawAddress& bd_addr,
                                          uint8_t res, uint32_t passkey) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
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
void bluetooth::shim::BTM_BleConfirmReply(const RawAddress& bd_addr,
                                          uint8_t res) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
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
void bluetooth::shim::BTM_BleOobDataReply(const RawAddress& bd_addr,
                                          uint8_t res, uint8_t len,
                                          uint8_t* p_data) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_data != nullptr);
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
void bluetooth::shim::BTM_BleSecureConnectionOobDataReply(
    const RawAddress& bd_addr, uint8_t* p_c, uint8_t* p_r) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_c != nullptr);
  CHECK(p_r != nullptr);
}

/******************************************************************************
 *
 * Function         BTM_BleSetConnScanParams
 *
 * Description      Set scan parameter used in BLE connection request
 *
 * Parameters:      scan_interval: scan interval
 *                  scan_window: scan window
 *
 * Returns          void
 *
 ******************************************************************************/
void bluetooth::shim::BTM_BleSetConnScanParams(uint32_t scan_interval,
                                               uint32_t scan_window) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
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
 *                  slave_latency    - preferred slave latency
 *                  supervision_tout - preferred supervision timeout
 *
 * Returns          void
 *
 ******************************************************************************/
void bluetooth::shim::BTM_BleSetPrefConnParams(const RawAddress& bd_addr,
                                               uint16_t min_conn_int,
                                               uint16_t max_conn_int,
                                               uint16_t slave_latency,
                                               uint16_t supervision_tout) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
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
void bluetooth::shim::BTM_ReadDevInfo(const RawAddress& remote_bda,
                                      tBT_DEVICE_TYPE* p_dev_type,
                                      tBLE_ADDR_TYPE* p_addr_type) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_dev_type != nullptr);
  CHECK(p_addr_type != nullptr);
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
bool bluetooth::shim::BTM_ReadConnectedTransportAddress(
    RawAddress* remote_bda, tBT_TRANSPORT transport) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(remote_bda != nullptr);
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
void bluetooth::shim::BTM_BleReceiverTest(uint8_t rx_freq,
                                          tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_cmd_cmpl_cback != nullptr);
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
void bluetooth::shim::BTM_BleTransmitterTest(uint8_t tx_freq,
                                             uint8_t test_data_len,
                                             uint8_t packet_payload,
                                             tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_cmd_cmpl_cback != nullptr);
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
void bluetooth::shim::BTM_BleTestEnd(tBTM_CMPL_CB* p_cmd_cmpl_cback) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_cmd_cmpl_cback != nullptr);
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
bool bluetooth::shim::BTM_UseLeLink(const RawAddress& raw_address) {
  return shim_btm.IsLeAclConnected(raw_address);
}

/*******************************************************************************
 *
 * Function         BTM_SetBleDataLength
 *
 * Description      This function is to set maximum BLE transmission packet size
 *
 * Returns          BTM_SUCCESS if success; otherwise failed.
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_SetBleDataLength(const RawAddress& bd_addr,
                                                  uint16_t tx_pdu_length) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return BTM_NO_RESOURCES;
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
void bluetooth::shim::BTM_BleReadPhy(
    const RawAddress& bd_addr,
    base::Callback<void(uint8_t tx_phy, uint8_t rx_phy, uint8_t status)> cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

/*******************************************************************************
 *
 * Function         BTM_BleSetDefaultPhy
 *
 * Description      To set preferred PHY for ensuing LE connections
 *
 *
 * Returns          BTM_SUCCESS if command successfully sent to controller,
 *                  BTM_MODE_UNSUPPORTED if local controller doesn't support LE
 *                  2M or LE Coded PHY
 *
 ******************************************************************************/
tBTM_STATUS bluetooth::shim::BTM_BleSetDefaultPhy(uint8_t all_phys,
                                                  uint8_t tx_phys,
                                                  uint8_t rx_phys) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return BTM_NO_RESOURCES;
}

/*******************************************************************************
 *
 * Function         BTM_BleSetPhy
 *
 * Description      To set PHY preferences for specified LE connection
 *
 *
 * Returns          BTM_SUCCESS if command successfully sent to controller,
 *                  BTM_MODE_UNSUPPORTED if local controller doesn't support LE
 *                  2M or LE Coded PHY,
 *                  BTM_ILLEGAL_VALUE if specified remote doesn't support LE 2M
 *                  or LE Coded PHY,
 *                  BTM_WRONG_MODE if Device in wrong mode for request.
 *
 ******************************************************************************/
void bluetooth::shim::BTM_BleSetPhy(const RawAddress& bd_addr, uint8_t tx_phys,
                                    uint8_t rx_phys, uint16_t phy_options) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
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
bool bluetooth::shim::BTM_BleDataSignature(const RawAddress& bd_addr,
                                           uint8_t* p_text, uint16_t len,
                                           BLE_SIGNATURE signature) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_text != nullptr);
  return false;
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
bool bluetooth::shim::BTM_BleVerifySignature(const RawAddress& bd_addr,
                                             uint8_t* p_orig, uint16_t len,
                                             uint32_t counter,
                                             uint8_t* p_comp) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_orig != nullptr);
  CHECK(p_comp != nullptr);
  return false;
}

/*******************************************************************************
 *
 * Function         BTM_GetLeSecurityState
 *
 * Description      This function is called to get security mode 1 flags and
 *                  encryption key size for LE peer.
 *
 * Returns          bool    true if LE device is found, false otherwise.
 *
 ******************************************************************************/
bool bluetooth::shim::BTM_GetLeSecurityState(const RawAddress& bd_addr,
                                             uint8_t* p_le_dev_sec_flags,
                                             uint8_t* p_le_key_size) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  CHECK(p_le_dev_sec_flags != nullptr);
  CHECK(p_le_key_size != nullptr);
  return false;
}

/*******************************************************************************
 *
 * Function         BTM_BleSecurityProcedureIsRunning
 *
 * Description      This function indicates if LE security procedure is
 *                  currently running with the peer.
 *
 * Returns          bool    true if security procedure is running, false
 *                  otherwise.
 *
 ******************************************************************************/
bool bluetooth::shim::BTM_BleSecurityProcedureIsRunning(
    const RawAddress& bd_addr) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return false;
}

/*******************************************************************************
 *
 * Function         BTM_BleGetSupportedKeySize
 *
 * Description      This function gets the maximum encryption key size in bytes
 *                  the local device can suport.
 *                  record.
 *
 * Returns          the key size or 0 if the size can't be retrieved.
 *
 ******************************************************************************/
uint8_t bluetooth::shim::BTM_BleGetSupportedKeySize(const RawAddress& bd_addr) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
  return 0;
}

/**
 * This function update(add,delete or clear) the adv local name filtering
 * condition.
 */
void bluetooth::shim::BTM_LE_PF_local_name(tBTM_BLE_SCAN_COND_OP action,
                                           tBTM_BLE_PF_FILT_INDEX filt_index,
                                           std::vector<uint8_t> name,
                                           tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_srvc_data(tBTM_BLE_SCAN_COND_OP action,
                                          tBTM_BLE_PF_FILT_INDEX filt_index) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_manu_data(
    tBTM_BLE_SCAN_COND_OP action, tBTM_BLE_PF_FILT_INDEX filt_index,
    uint16_t company_id, uint16_t company_id_mask, std::vector<uint8_t> data,
    std::vector<uint8_t> data_mask, tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_srvc_data_pattern(
    tBTM_BLE_SCAN_COND_OP action, tBTM_BLE_PF_FILT_INDEX filt_index,
    std::vector<uint8_t> data, std::vector<uint8_t> data_mask,
    tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_addr_filter(tBTM_BLE_SCAN_COND_OP action,
                                            tBTM_BLE_PF_FILT_INDEX filt_index,
                                            tBLE_BD_ADDR addr,
                                            tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_uuid_filter(tBTM_BLE_SCAN_COND_OP action,
                                            tBTM_BLE_PF_FILT_INDEX filt_index,
                                            tBTM_BLE_PF_COND_TYPE filter_type,
                                            const bluetooth::Uuid& uuid,
                                            tBTM_BLE_PF_LOGIC_TYPE cond_logic,
                                            const bluetooth::Uuid& uuid_mask,
                                            tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_set(tBTM_BLE_PF_FILT_INDEX filt_index,
                                    std::vector<ApcfCommand> commands,
                                    tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_LE_PF_clear(tBTM_BLE_PF_FILT_INDEX filt_index,
                                      tBTM_BLE_PF_CFG_CBACK cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleAdvFilterParamSetup(
    int action, tBTM_BLE_PF_FILT_INDEX filt_index,
    std::unique_ptr<btgatt_filt_param_setup_t> p_filt_params,
    tBTM_BLE_PF_PARAM_CB cb) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}

void bluetooth::shim::BTM_BleEnableDisableFilterFeature(
    uint8_t enable, tBTM_BLE_PF_STATUS_CBACK p_stat_cback) {
  LOG_INFO(LOG_TAG, "UNIMPLEMENTED %s", __func__);
}
