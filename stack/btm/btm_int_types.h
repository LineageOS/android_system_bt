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
#ifndef BTM_INT_TYPES_H
#define BTM_INT_TYPES_H

#include <cstdint>
#include <memory>
#include <string>

#include "gd/common/circular_buffer.h"
#include "osi/include/allocator.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/list.h"
#include "stack/acl/acl.h"
#include "stack/btm/btm_ble_int_types.h"
#include "stack/btm/btm_sco.h"
#include "stack/btm/neighbor_inquiry.h"
#include "stack/btm/security_device_record.h"
#include "stack/include/btm_ble_api_types.h"

#define BTM_SEC_IS_SM4(sm) ((bool)(BTM_SM4_TRUE == ((sm)&BTM_SM4_TRUE)))
#define BTM_SEC_IS_SM4_LEGACY(sm) ((bool)(BTM_SM4_KNOWN == ((sm)&BTM_SM4_TRUE)))
#define BTM_SEC_IS_SM4_UNKNOWN(sm) \
  ((bool)(BTM_SM4_UNKNOWN == ((sm)&BTM_SM4_TRUE)))

#define BTM_SEC_LE_MASK                              \
  (BTM_SEC_LE_AUTHENTICATED | BTM_SEC_LE_ENCRYPTED | \
   BTM_SEC_LE_LINK_KEY_KNOWN | BTM_SEC_LE_LINK_KEY_AUTHED)

#define BTM_MAX_SCN_ 31  // PORT_MAX_RFC_PORTS system/bt/stack/include/rfcdefs.h

constexpr size_t kMaxLogSize = 255;
class TimestampedStringCircularBuffer
    : public bluetooth::common::TimestampedCircularBuffer<std::string> {
 public:
  explicit TimestampedStringCircularBuffer(size_t size)
      : bluetooth::common::TimestampedCircularBuffer<std::string>(size) {}

  void Push(std::string s) {
    bluetooth::common::TimestampedCircularBuffer<std::string>::Push(
        s.substr(0, kMaxLogSize));
  }

  template <typename... Args>
  void Push(Args... args) {
    char buf[kMaxLogSize];
    std::snprintf(buf, sizeof(buf), args...);
    bluetooth::common::TimestampedCircularBuffer<std::string>::Push(
        std::string(buf));
  }
};

/*
 * Local device configuration
 */
typedef struct {
  tBTM_LOC_BD_NAME bd_name;  /* local Bluetooth device name */
  bool pin_type;             /* true if PIN type is fixed */
  uint8_t pin_code_len;      /* Bonding information */
  PIN_CODE pin_code;         /* PIN CODE if pin type is fixed */
} tBTM_CFG;

/* Pairing State */
enum {
  BTM_PAIR_STATE_IDLE, /* Idle                                         */
  BTM_PAIR_STATE_GET_REM_NAME, /* Getting the remote name (to check for SM4) */
  BTM_PAIR_STATE_WAIT_PIN_REQ, /* Started authentication, waiting for PIN req
                                  (PIN is pre-fetched) */
  BTM_PAIR_STATE_WAIT_LOCAL_PIN,       /* Waiting for local PIN code */
  BTM_PAIR_STATE_WAIT_NUMERIC_CONFIRM, /* Waiting user 'yes' to numeric
                                          confirmation   */
  BTM_PAIR_STATE_KEY_ENTRY, /* Key entry state (we are a keyboard)          */
  BTM_PAIR_STATE_WAIT_LOCAL_OOB_RSP, /* Waiting for local response to peer OOB
                                        data  */
  BTM_PAIR_STATE_WAIT_LOCAL_IOCAPS, /* Waiting for local IO capabilities and OOB
                                       data */
  BTM_PAIR_STATE_INCOMING_SSP, /* Incoming SSP (got peer IO caps when idle) */
  BTM_PAIR_STATE_WAIT_AUTH_COMPLETE, /* All done, waiting authentication
                                        cpmplete    */
  BTM_PAIR_STATE_WAIT_DISCONNECT     /* Waiting to disconnect the ACL */
};
typedef uint8_t tBTM_PAIRING_STATE;

#define BTM_PAIR_FLAGS_WE_STARTED_DD \
  0x01 /* We want to do dedicated bonding              */
#define BTM_PAIR_FLAGS_PEER_STARTED_DD \
  0x02 /* Peer initiated dedicated bonding             */
#define BTM_PAIR_FLAGS_DISC_WHEN_DONE 0x04 /* Disconnect when done     */
#define BTM_PAIR_FLAGS_PIN_REQD \
  0x08 /* set this bit when pin_callback is called     */
#define BTM_PAIR_FLAGS_PRE_FETCH_PIN \
  0x10 /* set this bit when pre-fetch pin     */
#define BTM_PAIR_FLAGS_REJECTED_CONNECT \
  0x20 /* set this bit when rejected incoming connection  */
#define BTM_PAIR_FLAGS_WE_CANCEL_DD \
  0x40 /* set this bit when cancelling a bonding procedure */
#define BTM_PAIR_FLAGS_LE_ACTIVE \
  0x80 /* use this bit when SMP pairing is active */

typedef struct {
  bool is_mux;
  RawAddress bd_addr;
  uint16_t psm;
  bool is_orig;
  tBTM_SEC_CALLBACK* p_callback;
  void* p_ref_data;
  uint16_t rfcomm_security_requirement;
  tBT_TRANSPORT transport;
  tBTM_BLE_SEC_ACT sec_act;
} tBTM_SEC_QUEUE_ENTRY;

// Bluetooth Quality Report - Report receiver
typedef void(tBTM_BT_QUALITY_REPORT_RECEIVER)(uint8_t len, uint8_t* p_stream);

/* Define a structure to hold all the BTM data
*/

#define BTM_STATE_BUFFER_SIZE 5 /* size of state buffer */

/* Define the Device Management control structure
 */
typedef struct {
  tBTM_VS_EVT_CB* p_vend_spec_cb[BTM_MAX_VSE_CALLBACKS]; /* Register for vendor
                                                            specific events  */

  tBTM_CMPL_CB*
      p_stored_link_key_cmpl_cb; /* Read/Write/Delete stored link key    */

  alarm_t* read_local_name_timer; /* Read local name timer */
  tBTM_CMPL_CB* p_rln_cmpl_cb;    /* Callback function to be called when  */
                                  /* read local name function complete    */

  alarm_t* read_rssi_timer;     /* Read RSSI timer */
  tBTM_CMPL_CB* p_rssi_cmpl_cb; /* Callback function to be called when  */
                                /* read RSSI function completes */

  alarm_t* read_failed_contact_counter_timer; /* Read Failed Contact Counter */
                                              /* timer */
  tBTM_CMPL_CB* p_failed_contact_counter_cmpl_cb; /* Callback function to be */
  /* called when read Failed Contact Counter function completes */

  alarm_t*
      read_automatic_flush_timeout_timer; /* Read Automatic Flush Timeout */
                                          /* timer */
  tBTM_CMPL_CB* p_automatic_flush_timeout_cmpl_cb; /* Callback function to be */
  /* called when read Automatic Flush Timeout function completes */

  alarm_t* read_link_quality_timer;
  tBTM_CMPL_CB* p_link_qual_cmpl_cb; /* Callback function to be called when  */
                                     /* read link quality function completes */

  alarm_t* read_tx_power_timer;     /* Read tx power timer */
  tBTM_CMPL_CB* p_tx_power_cmpl_cb; /* Callback function to be called       */

  DEV_CLASS dev_class; /* Local device class                   */

  tBTM_CMPL_CB*
      p_le_test_cmd_cmpl_cb; /* Callback function to be called when
                             LE test mode command has been sent successfully */

  RawAddress read_tx_pwr_addr; /* read TX power target address     */

  tBTM_BLE_LOCAL_ID_KEYS id_keys;   /* local BLE ID keys */
  Octet16 ble_encryption_key_value; /* BLE encryption key */

#if (BTM_BLE_CONFORMANCE_TESTING == TRUE)
  bool no_disc_if_pair_fail;
  bool enable_test_mac_val;
  BT_OCTET8 test_mac;
  bool enable_test_local_sign_cntr;
  uint32_t test_local_sign_cntr;
#endif

  tBTM_IO_CAP loc_io_caps;    /* IO capability of the local device */
  tBTM_AUTH_REQ loc_auth_req; /* the auth_req flag  */

  void Init() {
    read_local_name_timer = alarm_new("btm.read_local_name_timer");
    read_rssi_timer = alarm_new("btm.read_rssi_timer");
    read_failed_contact_counter_timer =
        alarm_new("btm.read_failed_contact_counter_timer");
    read_automatic_flush_timeout_timer =
        alarm_new("btm.read_automatic_flush_timeout_timer");
    read_link_quality_timer = alarm_new("btm.read_link_quality_timer");
    read_tx_power_timer = alarm_new("btm.read_tx_power_timer");
  }

  void Free() {
    alarm_free(read_local_name_timer);
    alarm_free(read_rssi_timer);
    alarm_free(read_failed_contact_counter_timer);
    alarm_free(read_automatic_flush_timeout_timer);
    alarm_free(read_link_quality_timer);
    alarm_free(read_tx_power_timer);
  }
} tBTM_DEVCB;

typedef struct {
  tBTM_CFG cfg; /* Device configuration */

  /*****************************************************
  **      Device control
  *****************************************************/
  tBTM_DEVCB devcb;

  /*****************************************************
  **      BLE Device controllers
  *****************************************************/
  tBTM_BLE_CB ble_ctr_cb;

 private:
  friend void btm_ble_ltk_request_reply(const RawAddress& bda, bool use_stk,
                                        const Octet16& stk);
  friend tBTM_STATUS btm_ble_start_encrypt(const RawAddress& bda, bool use_stk,
                                           Octet16* p_stk);
  friend void btm_ble_ltk_request_reply(const RawAddress& bda, bool use_stk,
                                        const Octet16& stk);
  uint16_t enc_handle{0};

  friend void btm_ble_ltk_request(uint16_t handle, uint8_t rand[8],
                                  uint16_t ediv);
  BT_OCTET8 enc_rand; /* received rand value from LTK request*/

  uint16_t ediv{0}; /* received ediv value from LTK request */

  uint8_t key_size{0};

 public:
  tBTM_BLE_VSC_CB cmn_ble_vsc_cb;

  /* Packet types supported by the local device */
  uint16_t btm_sco_pkt_types_supported{0};

  /*****************************************************
  **      Inquiry
  *****************************************************/
  tBTM_INQUIRY_VAR_ST btm_inq_vars;

  /*****************************************************
  **      SCO Management
  *****************************************************/
  tSCO_CB sco_cb;

  /*****************************************************
  **      Security Management
  *****************************************************/
  tBTM_APPL_INFO api;

#define BTM_SEC_MAX_RMT_NAME_CALLBACKS 2
  tBTM_RMT_NAME_CALLBACK* p_rmt_name_callback[BTM_SEC_MAX_RMT_NAME_CALLBACKS];

  tBTM_SEC_DEV_REC* p_collided_dev_rec{nullptr};
  alarm_t* sec_collision_timer{nullptr};
  uint64_t collision_start_time{0};
  uint32_t dev_rec_count{0}; /* Counter used for device record timestamp */
  uint8_t security_mode{0};
  bool pairing_disabled{false};
  bool security_mode_changed{false}; /* mode changed during bonding */
  bool pin_type_changed{false};      /* pin type changed during bonding */
  bool sec_req_pending{false};       /*   true if a request is pending */

  uint8_t pin_code_len{0};          /* for legacy devices */
  PIN_CODE pin_code;                /* for legacy devices */
  tBTM_PAIRING_STATE pairing_state{
      BTM_PAIR_STATE_IDLE};         /* The current pairing state    */
  uint8_t pairing_flags{0};         /* The current pairing flags    */
  RawAddress pairing_bda;           /* The device currently pairing */
  alarm_t* pairing_timer{nullptr};  /* Timer for pairing process    */
  uint16_t disc_handle{0};          /* for legacy devices */
  uint8_t disc_reason{0};           /* for legacy devices */
  tBTM_SEC_SERV_REC sec_serv_rec[BTM_SEC_MAX_SERVICE_RECORDS];
  list_t* sec_dev_rec{nullptr}; /* list of tBTM_SEC_DEV_REC */
  tBTM_SEC_SERV_REC* p_out_serv{nullptr};
  tBTM_MKEY_CALLBACK* mkey_cback{nullptr};

  RawAddress connecting_bda;
  DEV_CLASS connecting_dc;
  uint8_t trace_level;
  bool is_paging{false};  /* true, if paging is in progess */
  bool is_inquiry{false}; /* true, if inquiry is in progess */
  fixed_queue_t* page_queue{nullptr};

  bool paging{false};
  void set_paging() { paging = true; }
  void reset_paging() { paging = false; }
  bool is_paging_active() const {
    return paging;
  }  // TODO remove all this paging state

  fixed_queue_t* sec_pending_q{nullptr}; /* pending sequrity requests in
                                            tBTM_SEC_QUEUE_ENTRY format */

  // BQR Receiver
  tBTM_BT_QUALITY_REPORT_RECEIVER* p_bqr_report_receiver{nullptr};

  tACL_CB acl_cb_;

  std::shared_ptr<TimestampedStringCircularBuffer> history_{nullptr};

  void Init(uint8_t initial_security_mode) {
    memset(&cfg, 0, sizeof(cfg));
    memset(&devcb, 0, sizeof(devcb));
    memset(&ble_ctr_cb, 0, sizeof(ble_ctr_cb));
    memset(&enc_rand, 0, sizeof(enc_rand));
    memset(&cmn_ble_vsc_cb, 0, sizeof(cmn_ble_vsc_cb));
    memset(&btm_inq_vars, 0, sizeof(btm_inq_vars));
    memset(&sco_cb, 0, sizeof(sco_cb));
    memset(&api, 0, sizeof(api));
    memset(p_rmt_name_callback, 0, sizeof(p_rmt_name_callback));
    memset(&pin_code, 0, sizeof(pin_code));
    memset(sec_serv_rec, 0, sizeof(sec_serv_rec));

    connecting_bda = RawAddress::kEmpty;
    memset(&connecting_dc, 0, sizeof(connecting_dc));

    memset(&acl_cb_, 0, sizeof(acl_cb_));

    page_queue = fixed_queue_new(SIZE_MAX);
    sec_pending_q = fixed_queue_new(SIZE_MAX);
    sec_collision_timer = alarm_new("btm.sec_collision_timer");
    pairing_timer = alarm_new("btm.pairing_timer");

#if defined(BTM_INITIAL_TRACE_LEVEL)
    trace_level = BTM_INITIAL_TRACE_LEVEL;
#else
    trace_level = BT_TRACE_LEVEL_NONE; /* No traces */
#endif
    security_mode = initial_security_mode;
    pairing_bda = RawAddress::kAny;
    sec_dev_rec = list_new(osi_free);

    /* Initialize BTM component structures */
    btm_inq_vars.Init(); /* Inquiry Database and Structures */
    acl_cb_.Init();      /* ACL Database and Structures */
    sco_cb.Init();       /* SCO Database and Structures (If included) */
    devcb.Init();

    history_ = std::make_shared<TimestampedStringCircularBuffer>(40);
    CHECK(history_ != nullptr);
    history_->Push(std::string("Initialized btm history"));
  }

  void Free() {
    history_.reset();

    devcb.Free();
    btm_inq_vars.Free();

    fixed_queue_free(page_queue, nullptr);
    page_queue = nullptr;

    fixed_queue_free(sec_pending_q, nullptr);
    sec_pending_q = nullptr;

    list_free(sec_dev_rec);
    sec_dev_rec = nullptr;

    alarm_free(sec_collision_timer);
    sec_collision_timer = nullptr;

    alarm_free(pairing_timer);
    pairing_timer = nullptr;
  }

 private:
  friend uint8_t BTM_AllocateSCN(void);
  friend bool BTM_TryAllocateSCN(uint8_t scn);
  friend bool BTM_FreeSCN(uint8_t scn);
  uint8_t btm_scn[BTM_MAX_SCN_];
} tBTM_CB;

/* security action for L2CAP COC channels */
#define BTM_SEC_OK 1
#define BTM_SEC_ENCRYPT 2         /* encrypt the link with current key */
#define BTM_SEC_ENCRYPT_NO_MITM 3 /* unauthenticated encryption or better */
#define BTM_SEC_ENCRYPT_MITM 4    /* authenticated encryption */
#define BTM_SEC_ENC_PENDING 5     /* wait for link encryption pending */

typedef uint8_t tBTM_SEC_ACTION;

#endif  // BTM_INT_TYPES_H
