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

#pragma once

#include <unistd.h>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "async_manager.h"
#include "model/devices/device.h"
#include "phy_layer_factory.h"
#include "test_channel_transport.h"

namespace test_vendor_lib {

class TestModel {
 public:
  TestModel(
      std::function<AsyncUserId()> getNextUserId,
      std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                                const TaskCallback&)>
          evtScheduler,
      std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                                std::chrono::milliseconds, const TaskCallback&)>
          periodicEvtScheduler,
      std::function<void(AsyncUserId)> cancel_user_tasks,
      std::function<void(AsyncTaskId)> cancel,
      std::function<int(const std::string&, int)> connect_to_remote);
  ~TestModel() = default;

  TestModel(TestModel& model) = delete;
  TestModel& operator=(const TestModel& model) = delete;

  // Commands:

  // Add a device, return its index
  size_t Add(std::shared_ptr<Device> device);

  // Remove devices by index
  void Del(size_t device_index);

  // Add phy, return its index
  size_t AddPhy(Phy::Type phy_type);

  // Remove phy by index
  void DelPhy(size_t phy_index);

  // Add device to phy
  void AddDeviceToPhy(size_t device_index, size_t phy_index);

  // Remove device from phy
  void DelDeviceFromPhy(size_t device_index, size_t phy_index);

  // Handle incoming remote connections
  void AddLinkLayerConnection(int socket_fd, Phy::Type phy_type);
  void IncomingLinkLayerConnection(int socket_fd);
  void IncomingHciConnection(int socket_fd);

  // Handle closed remote connections
  void OnHciConnectionClosed(int socket_fd, size_t index, AsyncUserId user_id);

  // Connect to a remote device
  void AddRemote(const std::string& server, int port, Phy::Type phy_type);

  // Set the device's Bluetooth address
  void SetDeviceAddress(size_t device_index, Address device_address);

  // Let devices know about the passage of time
  void TimerTick();
  void StartTimer();
  void StopTimer();
  void SetTimerPeriod(std::chrono::milliseconds new_period);

  // List the devices that the test knows about
  const std::string& List();

  // Clear all devices and phys.
  void Reset();

 private:
  std::vector<PhyLayerFactory> phys_;
  std::vector<std::shared_ptr<Device>> devices_;
  std::string list_string_;

  // Callbacks to schedule tasks.
  std::function<AsyncUserId()> get_user_id_;
  std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                            const TaskCallback&)>
      schedule_task_;
  std::function<AsyncTaskId(AsyncUserId, std::chrono::milliseconds,
                            std::chrono::milliseconds, const TaskCallback&)>
      schedule_periodic_task_;
  std::function<void(AsyncTaskId)> cancel_task_;
  std::function<void(AsyncUserId)> cancel_tasks_from_user_;
  std::function<int(const std::string&, int)> connect_to_remote_;

  AsyncUserId model_user_id_;
  AsyncTaskId timer_tick_task_{kInvalidTaskId};
  std::chrono::milliseconds timer_period_{};

  std::vector<std::shared_ptr<Device>> example_devices_;
};

}  // namespace test_vendor_lib
