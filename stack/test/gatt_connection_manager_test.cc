#include "stack/gatt/connection_manager.h"

#include <base/bind.h>
#include <base/callback.h>
#include <base/location.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include "osi/include/alarm.h"

using testing::_;
using testing::Mock;
using testing::Return;
using testing::SaveArg;

namespace {
// convinience mock, for verifying whitelist operaitons on lower layer are
// actually scheduled
class WhiteListMock {
 public:
  MOCK_METHOD1(WhiteListAdd, bool(const RawAddress&));
  MOCK_METHOD1(WhiteListRemove, void(const RawAddress&));
  MOCK_METHOD0(WhiteListClear, void());
};

std::unique_ptr<WhiteListMock> localWhiteListMock;

}  // namespace

// Implementation of add/remove for test
bool BTM_WhiteListAdd(const RawAddress& address) {
  return localWhiteListMock->WhiteListAdd(address);
}

void BTM_WhiteListRemove(const RawAddress& address) {
  return localWhiteListMock->WhiteListRemove(address);
}

void BTM_WhiteListClear() { return localWhiteListMock->WhiteListClear(); }

RawAddress address1{{0x01, 0x01, 0x01, 0x01, 0x01, 0x01}};

constexpr tGATT_IF CLIENT1 = 1;
constexpr tGATT_IF CLIENT2 = 2;
constexpr tGATT_IF CLIENT3 = 3;
constexpr tGATT_IF CLIENT10 = 10;

namespace gatt {
namespace connection_manager {

class BleGattConnectionManager : public testing::Test {
  virtual void SetUp() {
    localWhiteListMock = std::make_unique<WhiteListMock>();
  }

  virtual void TearDown() {
    gatt::connection_manager::reset(true);
    localWhiteListMock.reset();
  }
};

/** Verify that app can add a device to white list, it is returned as interested
 * app, and then can remove the device later. */
TEST_F(BleGattConnectionManager, test_background_connection) {
  EXPECT_CALL(*localWhiteListMock, WhiteListAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*localWhiteListMock, WhiteListRemove(_)).Times(0);

  EXPECT_TRUE(background_connect_add(CLIENT1, address1));

  Mock::VerifyAndClearExpectations(localWhiteListMock.get());

  std::set<tGATT_IF> apps = get_apps_connecting_to(address1);
  EXPECT_EQ(apps.size(), 1UL);
  EXPECT_EQ(apps.count(CLIENT1), 1UL);

  EXPECT_CALL(*localWhiteListMock, WhiteListAdd(_)).Times(0);
  EXPECT_CALL(*localWhiteListMock, WhiteListRemove(address1)).Times(1);

  EXPECT_TRUE(background_connect_remove(CLIENT1, address1));

  EXPECT_EQ(get_apps_connecting_to(address1).size(), 0UL);

  Mock::VerifyAndClearExpectations(localWhiteListMock.get());
}

/** Verify that multiple clients adding same device multiple times, result in
 * device being added to whtie list only once, also, that device is removed only
 * after last client removes it. */
TEST_F(BleGattConnectionManager, test_background_connection_multiple_clients) {
  EXPECT_CALL(*localWhiteListMock, WhiteListAdd(address1))
      .WillOnce(Return(true));
  EXPECT_CALL(*localWhiteListMock, WhiteListRemove(_)).Times(0);
  EXPECT_TRUE(background_connect_add(CLIENT1, address1));
  EXPECT_TRUE(background_connect_add(CLIENT1, address1));
  EXPECT_TRUE(background_connect_add(CLIENT2, address1));
  EXPECT_TRUE(background_connect_add(CLIENT3, address1));

  EXPECT_EQ(get_apps_connecting_to(address1).size(), 3UL);

  Mock::VerifyAndClearExpectations(localWhiteListMock.get());

  EXPECT_CALL(*localWhiteListMock, WhiteListAdd(_)).Times(0);

  // removing from nonexisting client, should fail
  EXPECT_FALSE(background_connect_remove(CLIENT10, address1));

  EXPECT_TRUE(background_connect_remove(CLIENT1, address1));
  // already removed,  removing from same client twice should return false;
  EXPECT_FALSE(background_connect_remove(CLIENT1, address1));
  EXPECT_TRUE(background_connect_remove(CLIENT2, address1));

  EXPECT_CALL(*localWhiteListMock, WhiteListRemove(address1)).Times(1);
  EXPECT_TRUE(background_connect_remove(CLIENT3, address1));

  EXPECT_EQ(get_apps_connecting_to(address1).size(), 0UL);

  Mock::VerifyAndClearExpectations(localWhiteListMock.get());
}

}  // namespace connection_manager
}  // namespace gatt