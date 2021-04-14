/*
 * Copyright 2020 The Android Open Source Project
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

#include "hci/acl_manager/le_acl_connection.h"
#include "hci/acl_manager/le_connection_management_callbacks.h"
#include "os/metrics.h"

namespace bluetooth {
namespace hci {
namespace acl_manager {

class LeAclConnectionTracker : public LeConnectionManagementCallbacks {
 public:
  LeAclConnectionTracker(LeAclConnectionInterface* le_acl_connection_interface, uint16_t connection_handle)
      : le_acl_connection_interface_(le_acl_connection_interface), connection_handle_(connection_handle) {}
  ~LeAclConnectionTracker() {
    ASSERT(queued_callbacks_.empty());
  }
  void RegisterCallbacks(LeConnectionManagementCallbacks* callbacks, os::Handler* handler) {
    client_handler_ = handler;
    client_callbacks_ = callbacks;
    while (!queued_callbacks_.empty()) {
      auto iter = queued_callbacks_.begin();
      handler->Post(std::move(*iter));
      queued_callbacks_.erase(iter);
    }
  }

#define SAVE_OR_CALL(f, ...)                                                                                        \
  if (client_handler_ == nullptr) {                                                                                 \
    queued_callbacks_.emplace_back(                                                                                 \
        common::BindOnce(&LeConnectionManagementCallbacks::f, common::Unretained(this), __VA_ARGS__));              \
  } else {                                                                                                          \
    client_handler_->Post(                                                                                          \
        common::BindOnce(&LeConnectionManagementCallbacks::f, common::Unretained(client_callbacks_), __VA_ARGS__)); \
  }

  void OnConnectionUpdate(
      hci::ErrorCode hci_status, uint16_t conn_interval, uint16_t conn_latency, uint16_t supervision_timeout) override {
    SAVE_OR_CALL(OnConnectionUpdate, hci_status, conn_interval, conn_latency, supervision_timeout)
  }

  void OnDataLengthChange(uint16_t tx_octets, uint16_t tx_time, uint16_t rx_octets, uint16_t rx_time) override {
    SAVE_OR_CALL(OnDataLengthChange, tx_octets, tx_time, rx_octets, rx_time)
  }

  void OnReadRemoteVersionInformationComplete(
      hci::ErrorCode hci_status, uint8_t lmp_version, uint16_t manufacturer_name, uint16_t sub_version) {
    bluetooth::os::LogMetricRemoteVersionInfo(
        connection_handle_, static_cast<uint8_t>(hci_status), lmp_version, manufacturer_name, sub_version);
    SAVE_OR_CALL(OnReadRemoteVersionInformationComplete, hci_status, lmp_version, manufacturer_name, sub_version);
  }
  void OnPhyUpdate(hci::ErrorCode hci_status, uint8_t tx_phy, uint8_t rx_phy) override {
    SAVE_OR_CALL(OnPhyUpdate, hci_status, tx_phy, rx_phy);
  }
  void OnLocalAddressUpdate(AddressWithType address_with_type) override {
    SAVE_OR_CALL(OnLocalAddressUpdate, address_with_type);
  }

  void OnDisconnection(ErrorCode reason) override {
    SAVE_OR_CALL(OnDisconnection, reason);
  }
#undef SAVE_OR_CALL

  LeAclConnectionInterface* le_acl_connection_interface_;
  os::Handler* client_handler_ = nullptr;
  LeConnectionManagementCallbacks* client_callbacks_ = nullptr;
  std::list<common::OnceClosure> queued_callbacks_;
  uint16_t connection_handle_;
};

struct LeAclConnection::impl {
  impl(LeAclConnectionInterface* le_acl_connection_interface, std::shared_ptr<Queue> queue, uint16_t connection_handle)
      : queue_(std::move(queue)), tracker(le_acl_connection_interface, connection_handle) {}
  LeConnectionManagementCallbacks* GetEventCallbacks() {
    ASSERT(!callbacks_given_);
    callbacks_given_ = true;
    return &tracker;
  }

  bool callbacks_given_{false};
  std::shared_ptr<Queue> queue_;
  LeAclConnectionTracker tracker;
};

LeAclConnection::LeAclConnection()
    : AclConnection(), local_address_(Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS),
      remote_address_(Address::kEmpty, AddressType::PUBLIC_DEVICE_ADDRESS) {}

LeAclConnection::LeAclConnection(
    std::shared_ptr<Queue> queue,
    LeAclConnectionInterface* le_acl_connection_interface,
    uint16_t handle,
    AddressWithType local_address,
    AddressWithType remote_address,
    Role role)
    : AclConnection(queue->GetUpEnd(), handle),
      local_address_(local_address),
      remote_address_(remote_address),
      role_(role) {
  pimpl_ = new LeAclConnection::impl(le_acl_connection_interface, std::move(queue), handle);
}

LeAclConnection::~LeAclConnection() {
  delete pimpl_;
}

void LeAclConnection::RegisterCallbacks(LeConnectionManagementCallbacks* callbacks, os::Handler* handler) {
  return pimpl_->tracker.RegisterCallbacks(callbacks, handler);
}

void LeAclConnection::Disconnect(DisconnectReason reason) {
  pimpl_->tracker.le_acl_connection_interface_->EnqueueCommand(
      DisconnectBuilder::Create(handle_, reason),
      pimpl_->tracker.client_handler_->BindOnce([](CommandStatusView status) {
        ASSERT(status.IsValid());
        ASSERT(status.GetCommandOpCode() == OpCode::DISCONNECT);
        auto disconnect_status = DisconnectStatusView::Create(status);
        ASSERT(disconnect_status.IsValid());
        auto error_code = disconnect_status.GetStatus();
        if (error_code != ErrorCode::SUCCESS) {
          LOG_INFO("Disconnect status %s", ErrorCodeText(error_code).c_str());
        }
      }));
}

LeConnectionManagementCallbacks* LeAclConnection::GetEventCallbacks() {
  return pimpl_->GetEventCallbacks();
}

bool LeAclConnection::LeConnectionUpdate(uint16_t conn_interval_min, uint16_t conn_interval_max, uint16_t conn_latency,
                                         uint16_t supervision_timeout, uint16_t min_ce_length, uint16_t max_ce_length) {
  if (!check_connection_parameters(conn_interval_min, conn_interval_max, conn_latency, supervision_timeout)) {
    LOG_ERROR("Invalid parameter");
    return false;
  }
  pimpl_->tracker.le_acl_connection_interface_->EnqueueCommand(
      LeConnectionUpdateBuilder::Create(handle_, conn_interval_min, conn_interval_max, conn_latency,
                                        supervision_timeout, min_ce_length, max_ce_length),
      pimpl_->tracker.client_handler_->BindOnce([](CommandStatusView status) {
        ASSERT(status.IsValid());
        ASSERT(status.GetCommandOpCode() == OpCode::LE_CONNECTION_UPDATE);
      }));
  return true;
}

bool LeAclConnection::ReadRemoteVersionInformation() {
  pimpl_->tracker.le_acl_connection_interface_->EnqueueCommand(
      ReadRemoteVersionInformationBuilder::Create(handle_),
      pimpl_->tracker.client_handler_->BindOnce([](CommandStatusView status) {
        ASSERT(status.IsValid());
        ASSERT(status.GetCommandOpCode() == OpCode::READ_REMOTE_VERSION_INFORMATION);
      }));
  return true;
}

bool LeAclConnection::check_connection_parameters(
    uint16_t conn_interval_min, uint16_t conn_interval_max, uint16_t conn_latency, uint16_t supervision_timeout) {
  if (conn_interval_min < 0x0006 || conn_interval_min > 0x0C80 || conn_interval_max < 0x0006 ||
      conn_interval_max > 0x0C80 || conn_latency > 0x01F3 || supervision_timeout < 0x000A ||
      supervision_timeout > 0x0C80) {
    LOG_ERROR("Invalid parameter");
    return false;
  }
  // The Maximum interval in milliseconds will be conn_interval_max * 1.25 ms
  // The Timeout in milliseconds will be expected_supervision_timeout * 10 ms
  // The Timeout in milliseconds shall be larger than (1 + Latency) * Interval_Max * 2, where Interval_Max is given in
  // milliseconds.
  uint32_t supervision_timeout_min = (uint32_t)(1 + conn_latency) * conn_interval_max * 2 + 1;
  if (supervision_timeout * 8 < supervision_timeout_min || conn_interval_max < conn_interval_min) {
    LOG_ERROR("Invalid parameter");
    return false;
  }

  return true;
}

}  // namespace acl_manager
}  // namespace hci
}  // namespace bluetooth
