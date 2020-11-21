#include "stack/gatt/connection_manager.h"

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include "osi/include/alarm.h"
#include "osi/test/alarm_mock.h"

using testing::_;
using testing::DoAll;
using testing::Mock;
using testing::Return;
using testing::SaveArg;

using connection_manager::tAPP_ID;

namespace {
// convenience mock, for verifying acceptlist operations on lower layer are
// actually scheduled
class AcceptlistMock {
 public:
  MOCK_METHOD1(AcceptlistAdd, bool(const RawAddress&));
  MOCK_METHOD1(AcceptlistRemove, void(const RawAddress&));
  MOCK_METHOD0(AcceptlistClear, void());
  MOCK_METHOD0(SetLeConnectionModeToFast, bool());
  MOCK_METHOD0(SetLeConnectionModeToSlow, void());
  MOCK_METHOD2(OnConnectionTimedOut, void(uint8_t, const RawAddress&));
};

std::unique_ptr<AcceptlistMock> localAcceptlistMock;
}  // namespace

RawAddress address1{{0x01, 0x01, 0x01, 0x01, 0x01, 0x01}};
RawAddress address2{{0x22, 0x22, 0x02, 0x22, 0x33, 0x22}};

constexpr tAPP_ID CLIENT1 = 1;
constexpr tAPP_ID CLIENT2 = 2;
constexpr tAPP_ID CLIENT3 = 3;
constexpr tAPP_ID CLIENT10 = 10;

// Implementation of btm_ble_bgconn.h API for test.
bool BTM_AcceptlistAdd(const RawAddress& address) {
  return localAcceptlistMock->AcceptlistAdd(address);
}

void BTM_AcceptlistRemove(const RawAddress& address) {
  return localAcceptlistMock->AcceptlistRemove(address);
}

void BTM_AcceptlistClear() { return localAcceptlistMock->AcceptlistClear(); }

bool BTM_SetLeConnectionModeToFast() {
  return localAcceptlistMock->SetLeConnectionModeToFast();
}

void BTM_SetLeConnectionModeToSlow() {
  localAcceptlistMock->SetLeConnectionModeToSlow();
}

namespace bluetooth {
namespace shim {
bool is_gd_l2cap_enabled() { return false; }
}  // namespace shim
}  // namespace bluetooth

bool L2CA_ConnectFixedChnl(uint16_t fixed_cid, const RawAddress& bd_addr) {
  return false;
}

namespace connection_manager {
class BleConnectionManager : public testing::Test {
  void SetUp() override {
    localAcceptlistMock = std::make_unique<AcceptlistMock>();
  }

  void TearDown() override {
    connection_manager::reset(true);
    AlarmMock::Reset();
    localAcceptlistMock.reset();
  }
};

void on_connection_timed_out(uint8_t app_id, const RawAddress& address) {
  localAcceptlistMock->OnConnectionTimedOut(app_id, address);
}

/** Verify that app can add a device to acceptlist, it is returned as interested
 * app, and then can remove the device later. */
TEST_F(BleConnectionManager, test_background_connection_add_remove) {
  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(_)).Times(0);

  EXPECT_TRUE(background_connect_add(CLIENT1, address1));

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  std::set<tAPP_ID> apps = get_apps_connecting_to(address1);
  EXPECT_EQ(apps.size(), 1UL);
  EXPECT_EQ(apps.count(CLIENT1), 1UL);

  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(_)).Times(0);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(address1)).Times(1);

  EXPECT_TRUE(background_connect_remove(CLIENT1, address1));

  EXPECT_EQ(get_apps_connecting_to(address1).size(), 0UL);

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());
}

/** Verify that multiple clients adding same device multiple times, result in
 * device being added to whtie list only once, also, that device is removed only
 * after last client removes it. */
TEST_F(BleConnectionManager, test_background_connection_multiple_clients) {
  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(_)).Times(0);
  EXPECT_TRUE(background_connect_add(CLIENT1, address1));
  EXPECT_TRUE(background_connect_add(CLIENT1, address1));
  EXPECT_TRUE(background_connect_add(CLIENT2, address1));
  EXPECT_TRUE(background_connect_add(CLIENT3, address1));

  EXPECT_EQ(get_apps_connecting_to(address1).size(), 3UL);

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(_)).Times(0);

  // removing from nonexisting client, should fail
  EXPECT_FALSE(background_connect_remove(CLIENT10, address1));

  EXPECT_TRUE(background_connect_remove(CLIENT1, address1));
  // already removed,  removing from same client twice should return false;
  EXPECT_FALSE(background_connect_remove(CLIENT1, address1));
  EXPECT_TRUE(background_connect_remove(CLIENT2, address1));

  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(address1)).Times(1);
  EXPECT_TRUE(background_connect_remove(CLIENT3, address1));

  EXPECT_EQ(get_apps_connecting_to(address1).size(), 0UL);

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());
}

/** Verify adding/removing device to direct connection. */
TEST_F(BleConnectionManager, test_direct_connection_client) {
  // Direct connect attempt: use faster scan parameters, add to acceptlist,
  // start 30 timeout
  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToFast()).Times(1);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(_)).Times(0);
  EXPECT_CALL(*AlarmMock::Get(), AlarmNew(_)).Times(1);
  EXPECT_CALL(*AlarmMock::Get(), AlarmSetOnMloop(_, _, _, _)).Times(1);
  EXPECT_TRUE(direct_connect_add(CLIENT1, address1));

  // App already doing a direct connection, attempt to re-add result in failure
  EXPECT_FALSE(direct_connect_add(CLIENT1, address1));

  // Client that don't do direct connection should fail attempt to stop it
  EXPECT_FALSE(direct_connect_remove(CLIENT2, address1));

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToSlow()).Times(1);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(_)).Times(1);
  EXPECT_CALL(*AlarmMock::Get(), AlarmFree(_)).Times(1);

  // Removal should lower the connection parameters, and free the alarm.
  // Even though we call AcceptlistRemove, it won't be executed over HCI until
  // acceptlist is in use, i.e. next connection attempt
  EXPECT_TRUE(direct_connect_remove(CLIENT1, address1));

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());
}

/** Verify direct connection timeout does remove device from acceptlist, and
 * lower the connection scan parameters */
TEST_F(BleConnectionManager, test_direct_connect_timeout) {
  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToFast()).Times(1);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*AlarmMock::Get(), AlarmNew(_)).Times(1);
  alarm_callback_t alarm_callback = nullptr;
  void* alarm_data = nullptr;

  EXPECT_CALL(*AlarmMock::Get(), AlarmSetOnMloop(_, _, _, _))
      .Times(1)
      .WillOnce(DoAll(SaveArg<2>(&alarm_callback), SaveArg<3>(&alarm_data)));

  // Start direct connect attempt...
  EXPECT_TRUE(direct_connect_add(CLIENT1, address1));

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToSlow()).Times(1);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(_)).Times(1);
  EXPECT_CALL(*localAcceptlistMock, OnConnectionTimedOut(CLIENT1, address1))
      .Times(1);
  EXPECT_CALL(*AlarmMock::Get(), AlarmFree(_)).Times(1);

  // simulate timeout seconds passed, alarm executing
  alarm_callback(alarm_data);

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());
}

/** Verify that we properly handle successfull direct connection */
TEST_F(BleConnectionManager, test_direct_connection_success) {
  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToFast()).Times(1);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*AlarmMock::Get(), AlarmNew(_)).Times(1);
  EXPECT_CALL(*AlarmMock::Get(), AlarmSetOnMloop(_, _, _, _)).Times(1);

  // Start direct connect attempt...
  EXPECT_TRUE(direct_connect_add(CLIENT1, address1));

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToSlow()).Times(1);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(address1)).Times(1);
  EXPECT_CALL(*AlarmMock::Get(), AlarmFree(_)).Times(1);
  // simulate event from lower layers - connections was established
  // successfully.
  on_connection_complete(address1);
}

/** Verify that we properly handle application unregistration */
TEST_F(BleConnectionManager, test_app_unregister) {
  /* Test scenario:
   * - Client 1 connecting to address1 and address2.
   * - Client 2 connecting to address2
   * - unregistration of Client1 should trigger address1 removal from acceptlist
   * - unregistration of Client2 should trigger address2 removal
   */

  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address2))
      .WillOnce(Return(true));
  EXPECT_TRUE(direct_connect_add(CLIENT1, address1));
  EXPECT_TRUE(background_connect_add(CLIENT1, address2));
  EXPECT_TRUE(direct_connect_add(CLIENT2, address2));
  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(address1)).Times(1);
  on_app_deregistered(CLIENT1);
  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(address2)).Times(1);
  on_app_deregistered(CLIENT2);
}

/** Verify adding device to both direct connection and background connection. */
TEST_F(BleConnectionManager, test_direct_and_background_connect) {
  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToFast()).Times(1);
  EXPECT_CALL(*localAcceptlistMock, AcceptlistAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(_)).Times(0);
  EXPECT_CALL(*AlarmMock::Get(), AlarmNew(_)).Times(1);
  EXPECT_CALL(*AlarmMock::Get(), AlarmSetOnMloop(_, _, _, _)).Times(1);
  // add device as both direct and background connection
  EXPECT_TRUE(direct_connect_add(CLIENT1, address1));
  EXPECT_TRUE(background_connect_add(CLIENT1, address1));

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());

  EXPECT_CALL(*localAcceptlistMock, SetLeConnectionModeToSlow()).Times(1);
  EXPECT_CALL(*AlarmMock::Get(), AlarmFree(_)).Times(1);
  // not removing from acceptlist yet, as the background connection is still
  // pending.
  EXPECT_TRUE(direct_connect_remove(CLIENT1, address1));

  // remove from acceptlist, because no more interest in device.
  EXPECT_CALL(*localAcceptlistMock, AcceptlistRemove(_)).Times(1);
  EXPECT_TRUE(background_connect_remove(CLIENT1, address1));

  Mock::VerifyAndClearExpectations(localAcceptlistMock.get());
}

}  // namespace connection_manager
