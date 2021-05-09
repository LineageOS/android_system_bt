/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
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

#include <base/bind.h>
#include <base/bind_helpers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bta_gatt_api_mock.h"
#include "bta_gatt_queue_mock.h"
#include "bta_vc_api.h"
#include "btm_api_mock.h"
#include "gatt/database_builder.h"
#include "hardware/bt_gatt_types.h"
#include "types.h"

void btif_storage_add_volume_control(const RawAddress& addr, bool auto_conn) {}

namespace bluetooth {
namespace vc {
namespace internal {
namespace {

using base::Bind;
using base::Unretained;

using bluetooth::vc::ConnectionState;
using bluetooth::vc::VolumeControlCallbacks;

using testing::_;
using testing::DoAll;
using testing::DoDefault;
using testing::Invoke;
using testing::Mock;
using testing::NotNull;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using testing::WithArg;

RawAddress GetTestAddress(int index) {
  CHECK_LT(index, UINT8_MAX);
  RawAddress result = {
      {0xC0, 0xDE, 0xC0, 0xDE, 0x00, static_cast<uint8_t>(index)}};
  return result;
}

class MockVolumeControlCallbacks : public VolumeControlCallbacks {
 public:
  MockVolumeControlCallbacks() = default;
  ~MockVolumeControlCallbacks() override = default;

  MOCK_METHOD((void), OnConnectionState,
              (ConnectionState state, const RawAddress& address), (override));
  MOCK_METHOD((void), OnVolumeStateChanged,
              (const RawAddress& address, uint8_t volume, bool mute),
              (override));
  MOCK_METHOD((void), OnGroupVolumeStateChanged,
              (int group_id, uint8_t volume, bool mute), (override));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockVolumeControlCallbacks);
};

class VolumeControlTest : public ::testing::Test {
 private:
  void set_sample_database(uint16_t conn_id, bool vcs, bool vcs_broken,
                           bool aics, bool aics_broken, bool vocs,
                           bool vocs_broken) {
    gatt::DatabaseBuilder builder;
    builder.AddService(0x0001, 0x0003, Uuid::From16Bit(0x1800), true);
    builder.AddCharacteristic(0x0002, 0x0003, Uuid::From16Bit(0x2a00),
                              GATT_CHAR_PROP_BIT_READ);
    /* 0x0004-0x000f RFU */
    if (vcs) {
      /* VCS */
      builder.AddService(0x0010, 0x0026, kVolumeControlUuid, true);
      if (aics) {
        /* TODO Place holder */
      }
      if (vocs) {
        /* TODO Place holder */
      }
      /* 0x0015-0x001f RFU */
      builder.AddCharacteristic(
          0x0020, 0x0021, kVolumeControlStateUuid,
          GATT_CHAR_PROP_BIT_READ | GATT_CHAR_PROP_BIT_NOTIFY);
      builder.AddDescriptor(0x0022,
                            Uuid::From16Bit(GATT_UUID_CHAR_CLIENT_CONFIG));
      if (!vcs_broken) {
        builder.AddCharacteristic(0x0023, 0x0024, kVolumeControlPointUuid,
                                  GATT_CHAR_PROP_BIT_WRITE);
      }
      builder.AddCharacteristic(0x0025, 0x0026, kVolumeFlagsUuid,
                                GATT_CHAR_PROP_BIT_READ);
      /* 0x0027-0x002f RFU */
      if (aics) {
        /* TODO Place holder for AICS */
      }
      if (vocs) {
        /* TODO Place holder for VOCS */
      }
    }
    /* 0x008c-0x008f RFU */

    /* GATTS */
    builder.AddService(0x0090, 0x0093,
                       Uuid::From16Bit(UUID_SERVCLASS_GATT_SERVER), true);
    builder.AddCharacteristic(0x0091, 0x0092,
                              Uuid::From16Bit(GATT_UUID_GATT_SRV_CHGD),
                              GATT_CHAR_PROP_BIT_NOTIFY);
    builder.AddDescriptor(0x0093,
                          Uuid::From16Bit(GATT_UUID_CHAR_CLIENT_CONFIG));
    services_map[conn_id] = builder.Build().Services();

    ON_CALL(gatt_queue, ReadCharacteristic(conn_id, _, _, _))
        .WillByDefault(Invoke([&](uint16_t conn_id, uint16_t handle,
                                  GATT_READ_OP_CB cb, void* cb_data) -> void {
          std::vector<uint8_t> value;

          switch (handle) {
            case 0x0003:
              /* device name */
              value.resize(20);
              break;

            case 0x0021:
              /* volume state */
              value.resize(3);
              break;

            case 0x0026:
              /* volume flags */
              value.resize(1);
              break;

            default:
              ASSERT_TRUE(false);
              return;
          }

          cb(conn_id, GATT_SUCCESS, handle, value.size(), value.data(),
             cb_data);
        }));
  }

 protected:
  void SetUp(void) override {
    bluetooth::manager::SetMockBtmInterface(&btm_interface);
    gatt::SetMockBtaGattInterface(&gatt_interface);
    gatt::SetMockBtaGattQueue(&gatt_queue);
    callbacks.reset(new MockVolumeControlCallbacks());

    // default action for GetCharacteristic function call
    ON_CALL(gatt_interface, GetCharacteristic(_, _))
        .WillByDefault(
            Invoke([&](uint16_t conn_id,
                       uint16_t handle) -> const gatt::Characteristic* {
              std::list<gatt::Service>& services = services_map[conn_id];
              for (auto const& service : services) {
                for (auto const& characteristic : service.characteristics) {
                  if (characteristic.value_handle == handle) {
                    return &characteristic;
                  }
                }
              }

              return nullptr;
            }));

    // default action for GetOwningService function call
    ON_CALL(gatt_interface, GetOwningService(_, _))
        .WillByDefault(Invoke(
            [&](uint16_t conn_id, uint16_t handle) -> const gatt::Service* {
              std::list<gatt::Service>& services = services_map[conn_id];
              for (auto const& service : services) {
                if (service.handle <= handle && service.end_handle >= handle) {
                  return &service;
                }
              }

              return nullptr;
            }));

    // default action for GetServices function call
    ON_CALL(gatt_interface, GetServices(_))
        .WillByDefault(WithArg<0>(
            Invoke([&](uint16_t conn_id) -> std::list<gatt::Service>* {
              return &services_map[conn_id];
            })));

    // default action for RegisterForNotifications function call
    ON_CALL(gatt_interface, RegisterForNotifications(gatt_if, _, _))
        .WillByDefault(Return(GATT_SUCCESS));

    // default action for DeregisterForNotifications function call
    ON_CALL(gatt_interface, DeregisterForNotifications(gatt_if, _, _))
        .WillByDefault(Return(GATT_SUCCESS));

    // default action for WriteDescriptor function call
    ON_CALL(gatt_queue, WriteDescriptor(_, _, _, _, _, _))
        .WillByDefault(
            Invoke([](uint16_t conn_id, uint16_t handle,
                      std::vector<uint8_t> value, tGATT_WRITE_TYPE write_type,
                      GATT_WRITE_OP_CB cb, void* cb_data) -> void {
              if (cb) cb(conn_id, GATT_SUCCESS, handle, cb_data);
            }));
  }

  void TearDown(void) override {
    services_map.clear();
    callbacks.reset();
    gatt::SetMockBtaGattQueue(nullptr);
    gatt::SetMockBtaGattInterface(nullptr);
    bluetooth::manager::SetMockBtmInterface(nullptr);
  }

  void TestAppRegister(void) {
    BtaAppRegisterCallback app_register_callback;
    EXPECT_CALL(gatt_interface, AppRegister(_, _, _))
        .WillOnce(DoAll(SaveArg<0>(&gatt_callback),
                        SaveArg<1>(&app_register_callback)));
    VolumeControl::Initialize(callbacks.get());
    ASSERT_TRUE(gatt_callback);
    ASSERT_TRUE(app_register_callback);
    app_register_callback.Run(gatt_if, GATT_SUCCESS);
    ASSERT_TRUE(VolumeControl::IsVolumeControlRunning());
  }

  void TestAppUnregister(void) {
    EXPECT_CALL(gatt_interface, AppDeregister(gatt_if));
    VolumeControl::CleanUp();
    ASSERT_FALSE(VolumeControl::IsVolumeControlRunning());
    gatt_callback = nullptr;
  }

  void TestConnect(const RawAddress& address) {
    // by default indicate link as encrypted
    ON_CALL(btm_interface, GetSecurityFlagsByTransport(address, NotNull(), _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(BTM_SEC_FLAG_ENCRYPTED), Return(true)));

    EXPECT_CALL(gatt_interface, Open(gatt_if, address, true, _));
    VolumeControl::Get()->Connect(address);
  }

  void TestDisconnect(const RawAddress& address, uint16_t conn_id) {
    if (conn_id) {
      EXPECT_CALL(gatt_interface, Close(conn_id));
    } else {
      EXPECT_CALL(gatt_interface, CancelOpen(gatt_if, address, _));
    }
    VolumeControl::Get()->Disconnect(address);
  }

  void TestAddFromStorage(const RawAddress& address, bool auto_connect) {
    // by default indicate link as encrypted
    ON_CALL(btm_interface, GetSecurityFlagsByTransport(address, NotNull(), _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(BTM_SEC_FLAG_ENCRYPTED), Return(true)));

    if (auto_connect) {
      EXPECT_CALL(gatt_interface, Open(gatt_if, address, false, _));
    } else {
      EXPECT_CALL(gatt_interface, Open(gatt_if, address, _, _)).Times(0);
    }
    VolumeControl::Get()->AddFromStorage(address, auto_connect);
  }

  void TestSubscribeNotifications(const RawAddress& address, uint16_t conn_id,
                                  std::map<uint16_t, uint16_t>& handle_pairs) {
    SetSampleDatabase(conn_id);
    TestAppRegister();
    TestConnect(address);
    GetConnectedEvent(address, conn_id);

    EXPECT_CALL(gatt_queue, WriteDescriptor(_, _, _, _, _, _))
        .WillRepeatedly(DoDefault());
    EXPECT_CALL(gatt_interface, RegisterForNotifications(_, _, _))
        .WillRepeatedly(DoDefault());

    std::vector<uint8_t> notify_value({0x01, 0x00});
    for (auto const& handles : handle_pairs) {
      EXPECT_CALL(gatt_queue, WriteDescriptor(conn_id, handles.second,
                                              notify_value, GATT_WRITE, _, _))
          .WillOnce(DoDefault());
      EXPECT_CALL(gatt_interface,
                  RegisterForNotifications(gatt_if, address, handles.first))
          .WillOnce(DoDefault());
    }

    GetSearchCompleteEvent(conn_id);
    TestAppUnregister();
  }

  void TestReadCharacteristic(const RawAddress& address, uint16_t conn_id,
                              std::vector<uint16_t> handles) {
    SetSampleDatabase(conn_id);
    TestAppRegister();
    TestConnect(address);
    GetConnectedEvent(address, conn_id);

    EXPECT_CALL(gatt_queue, ReadCharacteristic(conn_id, _, _, _))
        .WillRepeatedly(DoDefault());
    for (auto const& handle : handles) {
      EXPECT_CALL(gatt_queue, ReadCharacteristic(conn_id, handle, _, _))
          .WillOnce(DoDefault());
    }

    GetSearchCompleteEvent(conn_id);
    TestAppUnregister();
  }

  void GetConnectedEvent(const RawAddress& address, uint16_t conn_id) {
    tBTA_GATTC_OPEN event_data = {
        .status = GATT_SUCCESS,
        .conn_id = conn_id,
        .client_if = gatt_if,
        .remote_bda = address,
        .transport = GATT_TRANSPORT_LE,
        .mtu = 240,
    };

    gatt_callback(BTA_GATTC_OPEN_EVT, (tBTA_GATTC*)&event_data);
  }

  void GetDisconnectedEvent(const RawAddress& address, uint16_t conn_id) {
    tBTA_GATTC_CLOSE event_data = {
        .status = GATT_SUCCESS,
        .conn_id = conn_id,
        .client_if = gatt_if,
        .remote_bda = address,
        .reason = GATT_CONN_TERMINATE_PEER_USER,
    };

    gatt_callback(BTA_GATTC_CLOSE_EVT, (tBTA_GATTC*)&event_data);
  }

  void GetSearchCompleteEvent(uint16_t conn_id) {
    tBTA_GATTC_SEARCH_CMPL event_data = {
        .status = GATT_SUCCESS,
        .conn_id = conn_id,
    };

    gatt_callback(BTA_GATTC_SEARCH_CMPL_EVT, (tBTA_GATTC*)&event_data);
  }

  void SetEncryptionResult(const RawAddress& address, bool success) {
    ON_CALL(btm_interface, GetSecurityFlagsByTransport(address, NotNull(), _))
        .WillByDefault(DoAll(SetArgPointee<1>(0), Return(true)));
    EXPECT_CALL(btm_interface,
                SetEncryption(address, _, NotNull(), _, BTM_BLE_SEC_ENCRYPT))
        .WillOnce(Invoke(
            [&success](const RawAddress& bd_addr, tBT_TRANSPORT transport,
                       tBTM_SEC_CALLBACK* p_callback, void* p_ref_data,
                       tBTM_BLE_SEC_ACT sec_act) -> tBTM_STATUS {
              p_callback(&bd_addr, transport, p_ref_data,
                         success ? BTM_SUCCESS : BTM_FAILED_ON_SECURITY);
              return BTM_SUCCESS;
            }));
  }

  void SetSampleDatabaseVCS(uint16_t conn_id) {
    set_sample_database(conn_id, true, false, false, false, false, false);
  }

  void SetSampleDatabaseNoVCS(uint16_t conn_id) {
    set_sample_database(conn_id, false, false, true, false, true, false);
  }

  void SetSampleDatabaseVCSBroken(uint16_t conn_id) {
    set_sample_database(conn_id, true, true, true, false, true, false);
  }

  void SetSampleDatabase(uint16_t conn_id) {
    set_sample_database(conn_id, true, false, true, false, true, false);
  }

  std::unique_ptr<MockVolumeControlCallbacks> callbacks;
  bluetooth::manager::MockBtmInterface btm_interface;
  gatt::MockBtaGattInterface gatt_interface;
  gatt::MockBtaGattQueue gatt_queue;
  tBTA_GATTC_CBACK* gatt_callback;
  const uint8_t gatt_if = 0xff;
  std::map<uint16_t, std::list<gatt::Service>> services_map;
};

TEST_F(VolumeControlTest, test_get_uninitialized) {
  ASSERT_DEATH(VolumeControl::Get(), "");
}

TEST_F(VolumeControlTest, test_initialize) {
  VolumeControl::Initialize(callbacks.get());
  ASSERT_TRUE(VolumeControl::IsVolumeControlRunning());
  VolumeControl::CleanUp();
}

TEST_F(VolumeControlTest, test_initialize_twice) {
  VolumeControl::Initialize(callbacks.get());
  VolumeControl* volume_control_p = VolumeControl::Get();
  VolumeControl::Initialize(callbacks.get());
  ASSERT_EQ(volume_control_p, VolumeControl::Get());
  VolumeControl::CleanUp();
}

TEST_F(VolumeControlTest, test_cleanup_initialized) {
  VolumeControl::Initialize(callbacks.get());
  VolumeControl::CleanUp();
  ASSERT_FALSE(VolumeControl::IsVolumeControlRunning());
}

TEST_F(VolumeControlTest, test_cleanup_uninitialized) {
  VolumeControl::CleanUp();
  ASSERT_FALSE(VolumeControl::IsVolumeControlRunning());
}

TEST_F(VolumeControlTest, test_app_registration) {
  TestAppRegister();
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_connect) {
  TestAppRegister();
  TestConnect(GetTestAddress(0));
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_add_from_storage) {
  TestAppRegister();
  TestAddFromStorage(GetTestAddress(0), true);
  TestAddFromStorage(GetTestAddress(1), false);
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_disconnect_non_connected) {
  const RawAddress test_address = GetTestAddress(0);
  TestAppRegister();
  TestConnect(test_address);
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::DISCONNECTED, test_address));
  TestDisconnect(test_address, 0);
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_disconnect_connected) {
  const RawAddress test_address = GetTestAddress(0);
  TestAppRegister();
  TestConnect(test_address);
  GetConnectedEvent(test_address, 1);
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::DISCONNECTED, test_address));
  TestDisconnect(test_address, 1);
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_disconnected) {
  const RawAddress test_address = GetTestAddress(0);
  TestAppRegister();
  TestConnect(test_address);
  GetConnectedEvent(test_address, 1);
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::DISCONNECTED, test_address));
  GetDisconnectedEvent(test_address, 1);
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_disconnected_while_autoconnect) {
  const RawAddress test_address = GetTestAddress(0);
  TestAppRegister();
  TestAddFromStorage(test_address, true);
  GetConnectedEvent(test_address, 1);
  // autoconnect - don't indicate disconnection
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::DISCONNECTED, test_address))
      .Times(0);
  GetDisconnectedEvent(test_address, 1);
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_reconnect_after_encryption_failed) {
  const RawAddress test_address = GetTestAddress(0);
  TestAppRegister();
  TestAddFromStorage(test_address, true);
  SetEncryptionResult(test_address, false);
  // autoconnect - don't indicate disconnection
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::DISCONNECTED, test_address))
      .Times(0);
  GetConnectedEvent(test_address, 1);
  Mock::VerifyAndClearExpectations(&btm_interface);
  SetEncryptionResult(test_address, true);
  GetConnectedEvent(test_address, 1);
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_discovery_vcs_found) {
  const RawAddress test_address = GetTestAddress(0);
  SetSampleDatabaseVCS(1);
  TestAppRegister();
  TestConnect(test_address);
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::CONNECTED, test_address));
  GetConnectedEvent(test_address, 1);
  GetSearchCompleteEvent(1);
  Mock::VerifyAndClearExpectations(callbacks.get());
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_discovery_vcs_not_found) {
  const RawAddress test_address = GetTestAddress(0);
  SetSampleDatabaseNoVCS(1);
  TestAppRegister();
  TestConnect(test_address);
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::DISCONNECTED, test_address));
  GetConnectedEvent(test_address, 1);

  GetSearchCompleteEvent(1);
  Mock::VerifyAndClearExpectations(callbacks.get());
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_discovery_vcs_broken) {
  const RawAddress test_address = GetTestAddress(0);
  SetSampleDatabaseVCSBroken(1);
  TestAppRegister();
  TestConnect(test_address);
  EXPECT_CALL(*callbacks,
              OnConnectionState(ConnectionState::DISCONNECTED, test_address));
  GetConnectedEvent(test_address, 1);
  GetSearchCompleteEvent(1);
  Mock::VerifyAndClearExpectations(callbacks.get());
  TestAppUnregister();
}

TEST_F(VolumeControlTest, test_subscribe_vcs_volume_state) {
  std::map<uint16_t, uint16_t> handles({{0x0021, 0x0022}});
  TestSubscribeNotifications(GetTestAddress(0), 1, handles);
}

TEST_F(VolumeControlTest, test_read_vcs_volume_state) {
  const RawAddress test_address = GetTestAddress(0);
  EXPECT_CALL(*callbacks, OnVolumeStateChanged(test_address, _, _));
  std::vector<uint16_t> handles({0x0021});
  TestReadCharacteristic(test_address, 1, handles);
}

TEST_F(VolumeControlTest, test_read_vcs_volume_flags) {
  std::vector<uint16_t> handles({0x0026});
  TestReadCharacteristic(GetTestAddress(0), 1, handles);
}

class VolumeControlCallbackTest : public VolumeControlTest {
 protected:
  const RawAddress test_address = GetTestAddress(0);
  uint16_t conn_id = 22;

  void SetUp(void) override {
    VolumeControlTest::SetUp();
    SetSampleDatabase(conn_id);
    TestAppRegister();
    TestConnect(test_address);
    GetConnectedEvent(test_address, conn_id);
    GetSearchCompleteEvent(conn_id);
  }

  void TearDown(void) override {
    TestAppUnregister();
    VolumeControlTest::TearDown();
  }

  void GetNotificationEvent(uint16_t handle, std::vector<uint8_t>& value) {
    tBTA_GATTC_NOTIFY event_data = {
        .conn_id = conn_id,
        .bda = test_address,
        .handle = handle,
        .len = (uint8_t)value.size(),
        .is_notify = true,
    };

    std::copy(value.begin(), value.end(), event_data.value);
    gatt_callback(BTA_GATTC_NOTIF_EVT, (tBTA_GATTC*)&event_data);
  }
};

TEST_F(VolumeControlCallbackTest, test_volume_state_changed) {
  std::vector<uint8_t> value({0x03, 0x01, 0x02});
  EXPECT_CALL(*callbacks, OnVolumeStateChanged(test_address, 0x03, true));
  GetNotificationEvent(0x0021, value);
}

TEST_F(VolumeControlCallbackTest, test_volume_state_changed_malformed) {
  EXPECT_CALL(*callbacks, OnVolumeStateChanged(test_address, _, _)).Times(0);
  std::vector<uint8_t> too_short({0x03, 0x01});
  GetNotificationEvent(0x0021, too_short);
  std::vector<uint8_t> too_long({0x03, 0x01, 0x02, 0x03});
  GetNotificationEvent(0x0021, too_long);
}

class VolumeControlValueSetTest : public VolumeControlTest {
 protected:
  const RawAddress test_address = GetTestAddress(0);
  uint16_t conn_id = 22;

  void SetUp(void) override {
    VolumeControlTest::SetUp();
    SetSampleDatabase(conn_id);
    TestAppRegister();
    TestConnect(test_address);
    GetConnectedEvent(test_address, conn_id);
    GetSearchCompleteEvent(conn_id);
  }

  void TearDown(void) override {
    TestAppUnregister();
    VolumeControlTest::TearDown();
  }
};

TEST_F(VolumeControlValueSetTest, test_set_volume) {
  std::vector<uint8_t> expected_data({0x04, 0x00, 0x10});
  EXPECT_CALL(gatt_queue, WriteCharacteristic(conn_id, 0x0024, expected_data,
                                              GATT_WRITE, _, _));
  VolumeControl::Get()->SetVolume(test_address, 0x10);
}
}  // namespace
}  // namespace internal
}  // namespace vc
}  // namespace bluetooth
