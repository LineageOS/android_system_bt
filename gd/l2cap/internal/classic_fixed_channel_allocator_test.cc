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

#include "l2cap/internal/classic_fixed_channel_allocator.h"

#include <gtest/gtest.h>

namespace bluetooth {
namespace l2cap {
namespace internal {

class L2capClassicFixedChannelAllocatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    thread_ = new os::Thread("test_thread", os::Thread::Priority::NORMAL);
    handler_ = new os::Handler(thread_);
    channel_allocator_ = std::make_unique<ClassicFixedChannelAllocator>(handler_);
  }

  void TearDown() override {
    channel_allocator_.reset();
    handler_->Clear();
    delete handler_;
    delete thread_;
  }

  os::Thread* thread_{nullptr};
  os::Handler* handler_{nullptr};
  std::unique_ptr<ClassicFixedChannelAllocator> channel_allocator_;
};

TEST_F(L2capClassicFixedChannelAllocatorTest, precondition) {
  Cid cid = kFirstFixedChannel;
  EXPECT_FALSE(channel_allocator_->IsChannelInUse(cid));
}

TEST_F(L2capClassicFixedChannelAllocatorTest, allocate_and_free_channel) {
  Cid cid = kFirstFixedChannel;
  auto* channel = channel_allocator_->AllocateChannel(cid, {});
  EXPECT_TRUE(channel_allocator_->IsChannelInUse(cid));
  EXPECT_EQ(channel, channel_allocator_->FindChannel(cid));
  EXPECT_TRUE(channel_allocator_->FreeChannel(cid));
  EXPECT_FALSE(channel_allocator_->IsChannelInUse(cid));
}

}  // namespace internal
}  // namespace l2cap
}  // namespace bluetooth
