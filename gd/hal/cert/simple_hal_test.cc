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

#include <grpc++/grpc++.h>
#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>

#include "hal/facade/api.grpc.pb.h"
#include "hci/hci_packets.h"
#include "os/log.h"

using grpc::ClientContext;

namespace bluetooth {
namespace hal {
namespace cert {

using ::bluetooth::hal::facade::HciCmdPacket;
using ::bluetooth::hal::facade::HciEvtPacket;
using ::bluetooth::hal::facade::HciTransportation;
using ::bluetooth::hal::facade::LoopbackModeSettings;

class HalAdapterCertTest : public ::testing::Test {
 protected:
  void SetUp() override {
    int port = 8899;
    std::string channel = "localhost:" + std::to_string(port);
    stub_ = HciTransportation::NewStub(grpc::CreateChannel(channel, grpc::InsecureChannelCredentials()));
  }
  void TearDown() override {
    stub_.reset();
  }

  std::unique_ptr<HciTransportation::Stub> stub_;
};

TEST_F(HalAdapterCertTest, enable_loopback_mode) {
  ClientContext set_loopback_mode_context;
  LoopbackModeSettings settings;
  settings.set_enable(true);
  ::google::protobuf::Empty empty;
  ::grpc::Status status = stub_->SetLoopbackMode(&set_loopback_mode_context, settings, &empty);
  EXPECT_EQ(status.ok(), true);

  ClientContext register_hci_evt_context;

  auto reader = stub_->RegisterHciEvt(&register_hci_evt_context, empty);

  auto packet = hci::DisconnectBuilder::Create(2, hci::DisconnectReason::PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED);
  std::shared_ptr<std::vector<uint8_t>> packet_bytes = std::make_shared<std::vector<uint8_t>>();
  hci::BitInserter it(*packet_bytes);
  packet->Serialize(it);

  std::string payload(packet_bytes->begin(), packet_bytes->end());

  ClientContext send_hci_cmd_context;
  HciCmdPacket cmd;
  cmd.set_payload(payload);
  status = stub_->SendHciCmd(&send_hci_cmd_context, cmd, &empty);
  EXPECT_EQ(status.ok(), true);

  HciEvtPacket received_packet;
  reader->Read(&received_packet);

  ClientContext unregister_hci_evt_context;

  status = stub_->UnregisterHciEvt(&unregister_hci_evt_context, empty, &empty);
  EXPECT_EQ(status.ok(), true);

  //  EXPECT_EQ(reader->Read(&received_packet), false);
}

}  // namespace cert
}  // namespace hal
}  // namespace bluetooth
