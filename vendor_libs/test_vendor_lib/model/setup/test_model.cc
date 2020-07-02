/*
 * Copyright 2018 The Android Open Source Project
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

#include "test_model.h"

// TODO: Remove when registration works
#include "model/devices/beacon.h"
#include "model/devices/beacon_swarm.h"
#include "model/devices/car_kit.h"
#include "model/devices/classic.h"
#include "model/devices/keyboard.h"
#include "model/devices/remote_loopback_device.h"
#include "model/devices/scripted_beacon.h"
#include "model/devices/sniffer.h"

#include <memory>

#include <stdlib.h>
#include <iomanip>
#include <iostream>

#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/values.h"

#include "os/log.h"
#include "osi/include/osi.h"

#include "device_boutique.h"
#include "include/phy.h"
#include "model/devices/hci_socket_device.h"
#include "model/devices/link_layer_socket_device.h"

using std::vector;

namespace test_vendor_lib {

TestModel::TestModel(
    std::function<AsyncTaskId(std::chrono::milliseconds, const TaskCallback&)> event_scheduler,

    std::function<AsyncTaskId(std::chrono::milliseconds, std::chrono::milliseconds, const TaskCallback&)>
        periodic_event_scheduler,

    std::function<void(AsyncTaskId)> cancel, std::function<int(const std::string&, int)> connect_to_remote)
    : schedule_task_(event_scheduler), schedule_periodic_task_(periodic_event_scheduler), cancel_task_(cancel),
      connect_to_remote_(connect_to_remote) {
  // TODO: Remove when registration works!
  example_devices_.push_back(std::make_shared<Beacon>());
  example_devices_.push_back(std::make_shared<BeaconSwarm>());
  example_devices_.push_back(std::make_shared<Keyboard>());
  example_devices_.push_back(std::make_shared<CarKit>());
  example_devices_.push_back(std::make_shared<Classic>());
  example_devices_.push_back(std::make_shared<Sniffer>());
  example_devices_.push_back(std::make_shared<ScriptedBeacon>());
  example_devices_.push_back(std::make_shared<RemoteLoopbackDevice>());
}

void TestModel::SetTimerPeriod(std::chrono::milliseconds new_period) {
  timer_period_ = new_period;

  if (timer_tick_task_ == kInvalidTaskId) return;

  // Restart the timer with the new period
  StopTimer();
  StartTimer();
}

void TestModel::StartTimer() {
  timer_tick_task_ =
      schedule_periodic_task_(std::chrono::milliseconds(0), timer_period_, [this]() { TestModel::TimerTick(); });
}

void TestModel::StopTimer() {
  cancel_task_(timer_tick_task_);
  timer_tick_task_ = kInvalidTaskId;
}

size_t TestModel::Add(std::shared_ptr<Device> new_dev) {
  devices_.push_back(new_dev);
  return devices_.size() - 1;
}

void TestModel::Del(size_t dev_index) {
  if (dev_index >= devices_.size() || devices_[dev_index] == nullptr) {
    LOG_WARN("Unknown device %zu", dev_index);
    return;
  }
  devices_[dev_index]->UnregisterPhyLayers();
  devices_[dev_index] = nullptr;
}

size_t TestModel::AddPhy(Phy::Type phy_type) {
  size_t factory_id = phys_.size();
  phys_.emplace_back(phy_type, factory_id);
  return factory_id;
}

void TestModel::DelPhy(size_t phy_index) {
  if (phy_index >= phys_.size()) {
    LOG_WARN("Unknown phy at index %zu", phy_index);
    return;
  }
  phys_[phy_index].UnregisterAllPhyLayers();
}

void TestModel::AddDeviceToPhy(size_t dev_index, size_t phy_index) {
  if (dev_index >= devices_.size() || devices_[dev_index] == nullptr) {
    LOG_WARN("Unknown device %zu", dev_index);
    return;
  }
  if (phy_index >= phys_.size()) {
    LOG_WARN("Can't find phy %zu", phy_index);
    return;
  }
  auto dev = devices_[dev_index];
  dev->RegisterPhyLayer(phys_[phy_index].GetPhyLayer(
      [dev](model::packets::LinkLayerPacketView packet) {
        dev->IncomingPacket(packet);
      },
      dev_index));
}

void TestModel::DelDeviceFromPhy(size_t dev_index, size_t phy_index) {
  if (dev_index >= devices_.size() || devices_[dev_index] == nullptr) {
    LOG_WARN("Unknown device %zu", dev_index);
    return;
  }
  if (phy_index >= phys_.size()) {
    LOG_WARN("Can't find phy %zu", phy_index);
    return;
  }
  devices_[dev_index]->UnregisterPhyLayer(phys_[phy_index].GetType(),
                                          phys_[phy_index].GetFactoryId());
}

void TestModel::AddLinkLayerConnection(int socket_fd, Phy::Type phy_type) {
  std::shared_ptr<Device> dev = LinkLayerSocketDevice::Create(socket_fd, phy_type);
  int index = Add(dev);
  for (size_t i = 0; i < phys_.size(); i++) {
    if (phy_type == phys_[i].GetType()) {
      AddDeviceToPhy(index, i);
    }
  }
}

void TestModel::IncomingLinkLayerConnection(int socket_fd) {
  // TODO: Handle other phys
  AddLinkLayerConnection(socket_fd, Phy::Type::BR_EDR);
}

void TestModel::AddRemote(const std::string& server, int port, Phy::Type phy_type) {
  int socket_fd = connect_to_remote_(server, port);
  if (socket_fd < 0) {
    return;
  }
  AddLinkLayerConnection(socket_fd, phy_type);
}

void TestModel::IncomingHciConnection(int socket_fd) {
  auto dev = HciSocketDevice::Create(socket_fd);
  size_t index = Add(std::static_pointer_cast<Device>(dev));
  std::string addr = "da:4c:10:de:17:";  // Da HCI dev
  std::stringstream stream;
  stream << std::setfill('0') << std::setw(2) << std::hex << (index % 256);
  addr += stream.str();

  dev->Initialize({"IgnoredTypeName", addr});
  LOG_INFO("initialized %s", addr.c_str());
  for (size_t i = 0; i < phys_.size(); i++) {
    AddDeviceToPhy(index, i);
  }
  dev->RegisterTaskScheduler(schedule_task_);
  dev->RegisterTaskCancel(cancel_task_);
  dev->RegisterCloseCallback([this, socket_fd, index] { OnHciConnectionClosed(socket_fd, index); });
}

void TestModel::OnHciConnectionClosed(int socket_fd, size_t index) {
  if (index >= devices_.size() || devices_[index] == nullptr) {
    LOG_WARN("Unknown device %zu", index);
    return;
  }
  int close_result = close(socket_fd);
  ASSERT_LOG(close_result == 0, "can't close: %s", strerror(errno));
  devices_[index]->UnregisterPhyLayers();
  devices_[index] = nullptr;
}

void TestModel::SetDeviceAddress(size_t index, Address address) {
  if (index >= devices_.size() || devices_[index] == nullptr) {
    LOG_WARN("Can't find device %zu", index);
    return;
  }
  devices_[index]->SetAddress(address);
}

const std::string& TestModel::List() {
  list_string_ = "";
  list_string_ += " Devices: \r\n";
  for (size_t i = 0; i < devices_.size(); i++) {
    list_string_ += "  " + std::to_string(i) + ":";
    if (devices_[i] == nullptr) {
      list_string_ += " deleted \r\n";
    } else {
      list_string_ += devices_[i]->ToString() + " \r\n";
    }
  }
  list_string_ += " Phys: \r\n";
  for (size_t i = 0; i < phys_.size(); i++) {
    list_string_ += "  " + std::to_string(i) + ":";
    list_string_ += phys_[i].ToString() + " \r\n";
  }
  return list_string_;
}

void TestModel::TimerTick() {
  for (const auto& dev : devices_) {
    if (dev != nullptr) {
      dev->TimerTick();
    }
  }
}

void TestModel::Reset() {
  StopTimer();
  for (auto& phy : phys_) {
    phy.UnregisterAllPhyLayers();
  }
  for (size_t i = 0; i < devices_.size(); i++) {
    Del(i);
  }
}

}  // namespace test_vendor_lib
