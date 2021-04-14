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

#include "hal/hci_hal_host.h"

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <mutex>
#include <queue>

#include "hal/hci_hal.h"
#include "hal/snoop_logger.h"
#include "os/log.h"
#include "os/reactor.h"
#include "os/thread.h"

namespace {
constexpr int INVALID_FD = -1;

constexpr uint8_t kH4Command = 0x01;
constexpr uint8_t kH4Acl = 0x02;
constexpr uint8_t kH4Sco = 0x03;
constexpr uint8_t kH4Event = 0x04;
constexpr uint8_t kH4Iso = 0x05;

constexpr uint8_t kH4HeaderSize = 1;
constexpr uint8_t kHciAclHeaderSize = 4;
constexpr uint8_t kHciScoHeaderSize = 3;
constexpr uint8_t kHciEvtHeaderSize = 2;
constexpr uint8_t kHciIsoHeaderSize = 4;
constexpr int kBufSize = 1024 + 4 + 1;  // DeviceProperties::acl_data_packet_size_ + ACL header + H4 header

#ifdef USE_LINUX_HCI_SOCKET
constexpr uint8_t BTPROTO_HCI = 1;
constexpr uint16_t HCI_CHANNEL_USER = 1;
constexpr uint16_t HCI_CHANNEL_CONTROL = 3;
constexpr uint16_t HCI_DEV_NONE = 0xffff;

/* reference from <kernel>/include/net/bluetooth/mgmt.h */
#define MGMT_OP_INDEX_LIST 0x0003
#define MGMT_EV_INDEX_ADDED 0x0004
#define MGMT_EV_COMMAND_COMP 0x0001
#define MGMT_EV_SIZE_MAX 1024
#define WRITE_NO_INTR(fn) \
  do {                    \
  } while ((fn) == -1 && errno == EINTR)

struct sockaddr_hci {
  sa_family_t hci_family;
  unsigned short hci_dev;
  unsigned short hci_channel;
};

struct mgmt_pkt {
  uint16_t opcode;
  uint16_t index;
  uint16_t len;
  uint8_t data[MGMT_EV_SIZE_MAX];
} __attribute__((packed));

struct mgmt_event_read_index {
  uint16_t cc_opcode;
  uint8_t status;
  uint16_t num_intf;
  uint16_t index[0];
} __attribute__((packed));

int waitHciDev(int hci_interface) {
  struct sockaddr_hci addr;
  struct pollfd fds[1];
  struct mgmt_pkt ev;
  int fd;
  int ret = 0;

  fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
  if (fd < 0) {
    LOG_ERROR("Bluetooth socket error: %s", strerror(errno));
    return -1;
  }
  memset(&addr, 0, sizeof(addr));
  addr.hci_family = AF_BLUETOOTH;
  addr.hci_dev = HCI_DEV_NONE;
  addr.hci_channel = HCI_CHANNEL_CONTROL;
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    LOG_ERROR("HCI Channel Control: %s", strerror(errno));
    close(fd);
    return -1;
  }

  fds[0].fd = fd;
  fds[0].events = POLLIN;

  /* Read Controller Index List Command */
  ev.opcode = MGMT_OP_INDEX_LIST;
  ev.index = HCI_DEV_NONE;
  ev.len = 0;

  ssize_t wrote;
  WRITE_NO_INTR(wrote = write(fd, &ev, 6));
  if (wrote != 6) {
    LOG_ERROR("Unable to write mgmt command: %s", strerror(errno));
    close(fd);
    return -1;
  }
  /* validate mentioned hci interface is present and registered with sock system */
  while (1) {
    int n;
    WRITE_NO_INTR(n = poll(fds, 1, -1));
    if (n == -1) {
      LOG_ERROR("Poll error: %s", strerror(errno));
      ret = -1;
      break;
    } else if (n == 0) {
      LOG_ERROR("Timeout, no HCI device detected");
      ret = -1;
      break;
    }

    if (fds[0].revents & POLLIN) {
      WRITE_NO_INTR(n = read(fd, &ev, sizeof(struct mgmt_pkt)));
      if (n < 0) {
        LOG_ERROR("Error reading control channel: %s", strerror(errno));
        ret = -1;
        break;
      }

      if (ev.opcode == MGMT_EV_INDEX_ADDED && ev.index == hci_interface) {
        close(fd);
        return -1;
      } else if (ev.opcode == MGMT_EV_COMMAND_COMP) {
        struct mgmt_event_read_index* cc;
        int i;

        cc = (struct mgmt_event_read_index*)ev.data;

        if (cc->cc_opcode != MGMT_OP_INDEX_LIST || cc->status != 0) continue;

        for (i = 0; i < cc->num_intf; i++) {
          if (cc->index[i] == hci_interface) {
            close(fd);
            return 0;
          }
        }
      }
    }
  }

  close(fd);
  return -1;
}

// Connect to Linux HCI socket
int ConnectToSocket() {
  int socket_fd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
  if (socket_fd < 1) {
    LOG_ERROR("can't create socket: %s", strerror(errno));
    return INVALID_FD;
  }

  int hci_interface = 0;  // Assume we only have HCI 0

  if (waitHciDev(hci_interface) != 0) {
    ::close(socket_fd);
    return INVALID_FD;
  }

  struct sockaddr_hci addr;
  memset(&addr, 0, sizeof(addr));
  addr.hci_family = AF_BLUETOOTH;
  addr.hci_dev = hci_interface;
  addr.hci_channel = HCI_CHANNEL_USER;
  if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    LOG_ERROR("HCI Channel Control: %s", strerror(errno));
    ::close(socket_fd);
    return INVALID_FD;
  }
  LOG_INFO("HCI device ready");
  return socket_fd;
}
#else
// Connect to root canal socket
int ConnectToSocket() {
  auto* config = bluetooth::hal::HciHalHostRootcanalConfig::Get();
  const std::string& server = config->GetServerAddress();
  int port = config->GetPort();

  int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_fd < 1) {
    LOG_ERROR("can't create socket: %s", strerror(errno));
    return INVALID_FD;
  }

  struct hostent* host;
  host = gethostbyname(server.c_str());
  if (host == nullptr) {
    LOG_ERROR("can't get server name");
    return INVALID_FD;
  }

  struct sockaddr_in serv_addr;
  memset((void*)&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(port);

  int result = connect(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
  if (result < 0) {
    LOG_ERROR("can't connect: %s", strerror(errno));
    return INVALID_FD;
  }

  timeval socket_timeout{
      .tv_sec = 3,
      .tv_usec = 0,
  };
  int ret = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout, sizeof(socket_timeout));
  if (ret == -1) {
    LOG_ERROR("can't control socket fd: %s", strerror(errno));
    return INVALID_FD;
  }
  return socket_fd;
}
#endif
}  // namespace

namespace bluetooth {
namespace hal {

class HciHalHost : public HciHal {
 public:
  void registerIncomingPacketCallback(HciHalCallbacks* callback) override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    LOG_INFO("%s before", __func__);
    {
      std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
      ASSERT(incoming_packet_callback_ == nullptr && callback != nullptr);
      incoming_packet_callback_ = callback;
    }
    LOG_INFO("%s after", __func__);
  }

  void unregisterIncomingPacketCallback() override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    LOG_INFO("%s before", __func__);
    {
      std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
      incoming_packet_callback_ = nullptr;
    }
    LOG_INFO("%s after", __func__);
  }

  void sendHciCommand(HciPacket command) override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    ASSERT(sock_fd_ != INVALID_FD);
    std::vector<uint8_t> packet = std::move(command);
    btsnoop_logger_->Capture(packet, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::CMD);
    packet.insert(packet.cbegin(), kH4Command);
    write_to_fd(packet);
  }

  void sendAclData(HciPacket data) override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    ASSERT(sock_fd_ != INVALID_FD);
    std::vector<uint8_t> packet = std::move(data);
    btsnoop_logger_->Capture(packet, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ACL);
    packet.insert(packet.cbegin(), kH4Acl);
    write_to_fd(packet);
  }

  void sendScoData(HciPacket data) override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    ASSERT(sock_fd_ != INVALID_FD);
    std::vector<uint8_t> packet = std::move(data);
    btsnoop_logger_->Capture(packet, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::SCO);
    packet.insert(packet.cbegin(), kH4Sco);
    write_to_fd(packet);
  }

  void sendIsoData(HciPacket data) override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    ASSERT(sock_fd_ != INVALID_FD);
    std::vector<uint8_t> packet = std::move(data);
    btsnoop_logger_->Capture(packet, SnoopLogger::Direction::OUTGOING, SnoopLogger::PacketType::ISO);
    packet.insert(packet.cbegin(), kH4Iso);
    write_to_fd(packet);
  }

 protected:
  void ListDependencies(ModuleList* list) override {
    list->add<SnoopLogger>();
  }

  void Start() override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    ASSERT(sock_fd_ == INVALID_FD);
    sock_fd_ = ConnectToSocket();
    ASSERT(sock_fd_ != INVALID_FD);
    reactable_ = hci_incoming_thread_.GetReactor()->Register(
        sock_fd_, common::Bind(&HciHalHost::incoming_packet_received, common::Unretained(this)), common::Closure());
    btsnoop_logger_ = GetDependency<SnoopLogger>();
    LOG_INFO("HAL opened successfully");
  }

  void Stop() override {
    std::lock_guard<std::mutex> lock(api_mutex_);
    LOG_INFO("HAL is closing");
    if (reactable_ != nullptr) {
      hci_incoming_thread_.GetReactor()->Unregister(reactable_);
      LOG_INFO("HAL is stopping, start waiting for last callback");
      // Wait up to 1 second for the last incoming packet callback to finish
      hci_incoming_thread_.GetReactor()->WaitForUnregisteredReactable(std::chrono::milliseconds(1000));
      LOG_INFO("HAL is stopping, finished waiting for last callback");
      ASSERT(sock_fd_ != INVALID_FD);
    }
    reactable_ = nullptr;
    {
      std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
      incoming_packet_callback_ = nullptr;
    }
    ::close(sock_fd_);
    sock_fd_ = INVALID_FD;
    LOG_INFO("HAL is closed");
  }

  std::string ToString() const override {
    return std::string("HciHalHost");
  }

 private:
  // Held when APIs are called, NOT to be held during callbacks
  std::mutex api_mutex_;
  HciHalCallbacks* incoming_packet_callback_ = nullptr;
  std::mutex incoming_packet_callback_mutex_;
  int sock_fd_ = INVALID_FD;
  bluetooth::os::Thread hci_incoming_thread_ =
      bluetooth::os::Thread("hci_incoming_thread", bluetooth::os::Thread::Priority::NORMAL);
  bluetooth::os::Reactor::Reactable* reactable_ = nullptr;
  std::queue<std::vector<uint8_t>> hci_outgoing_queue_;
  SnoopLogger* btsnoop_logger_ = nullptr;

  void write_to_fd(HciPacket packet) {
    // TODO: replace this with new queue when it's ready
    hci_outgoing_queue_.emplace(packet);
    if (hci_outgoing_queue_.size() == 1) {
      hci_incoming_thread_.GetReactor()->ModifyRegistration(
          reactable_,
          common::Bind(&HciHalHost::incoming_packet_received, common::Unretained(this)),
          common::Bind(&HciHalHost::send_packet_ready, common::Unretained(this)));
    }
  }

  void send_packet_ready() {
    std::lock_guard<std::mutex> lock(this->api_mutex_);
    auto packet_to_send = this->hci_outgoing_queue_.front();
    auto bytes_written = write(this->sock_fd_, (void*)packet_to_send.data(), packet_to_send.size());
    this->hci_outgoing_queue_.pop();
    if (bytes_written == -1) {
      abort();
    }
    if (hci_outgoing_queue_.empty()) {
      this->hci_incoming_thread_.GetReactor()->ModifyRegistration(
          this->reactable_,
          common::Bind(&HciHalHost::incoming_packet_received, common::Unretained(this)),
          common::Closure());
    }
  }

  void incoming_packet_received() {
    {
      std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
      if (incoming_packet_callback_ == nullptr) {
        LOG_INFO("Dropping a packet");
        return;
      }
    }
    uint8_t buf[kBufSize] = {};

    ssize_t received_size;
    RUN_NO_INTR(received_size = recv(sock_fd_, buf, kH4HeaderSize, 0));
    ASSERT_LOG(received_size != -1, "Can't receive from socket: %s", strerror(errno));
    if (received_size == 0) {
      LOG_WARN("Can't read H4 header. EOF received");
      raise(SIGINT);
      return;
    }

    if (buf[0] == kH4Event) {
      RUN_NO_INTR(received_size = recv(sock_fd_, buf + kH4HeaderSize, kHciEvtHeaderSize, 0));
      ASSERT_LOG(received_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(received_size == kHciEvtHeaderSize, "malformed HCI event header received");

      uint8_t hci_evt_parameter_total_length = buf[2];
      ssize_t payload_size;
      RUN_NO_INTR(
          payload_size = recv(sock_fd_, buf + kH4HeaderSize + kHciEvtHeaderSize, hci_evt_parameter_total_length, 0));
      ASSERT_LOG(payload_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(
          payload_size == hci_evt_parameter_total_length,
          "malformed HCI event total parameter size received: %zu != %d",
          payload_size,
          hci_evt_parameter_total_length);

      HciPacket receivedHciPacket;
      receivedHciPacket.assign(buf + kH4HeaderSize, buf + kH4HeaderSize + kHciEvtHeaderSize + payload_size);
      btsnoop_logger_->Capture(receivedHciPacket, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::EVT);
      {
        std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
        if (incoming_packet_callback_ == nullptr) {
          LOG_INFO("Dropping an event after processing");
          return;
        }
        incoming_packet_callback_->hciEventReceived(receivedHciPacket);
      }
    }

    if (buf[0] == kH4Acl) {
      RUN_NO_INTR(received_size = recv(sock_fd_, buf + kH4HeaderSize, kHciAclHeaderSize, 0));
      ASSERT_LOG(received_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(received_size == kHciAclHeaderSize, "malformed ACL header received");

      uint16_t hci_acl_data_total_length = (buf[4] << 8) + buf[3];
      int payload_size;
      RUN_NO_INTR(payload_size = recv(sock_fd_, buf + kH4HeaderSize + kHciAclHeaderSize, hci_acl_data_total_length, 0));
      ASSERT_LOG(payload_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(
          payload_size == hci_acl_data_total_length,
          "malformed ACL length received: %d != %d",
          payload_size,
          hci_acl_data_total_length);
      ASSERT_LOG(hci_acl_data_total_length <= kBufSize - kH4HeaderSize - kHciAclHeaderSize, "packet too long");

      HciPacket receivedHciPacket;
      receivedHciPacket.assign(buf + kH4HeaderSize, buf + kH4HeaderSize + kHciAclHeaderSize + payload_size);
      btsnoop_logger_->Capture(receivedHciPacket, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::ACL);
      {
        std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
        if (incoming_packet_callback_ == nullptr) {
          LOG_INFO("Dropping an ACL packet after processing");
          return;
        }
        incoming_packet_callback_->aclDataReceived(receivedHciPacket);
      }
    }

    if (buf[0] == kH4Sco) {
      RUN_NO_INTR(received_size = recv(sock_fd_, buf + kH4HeaderSize, kHciScoHeaderSize, 0));
      ASSERT_LOG(received_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(received_size == kHciScoHeaderSize, "malformed SCO header received");

      uint8_t hci_sco_data_total_length = buf[3];
      int payload_size;
      RUN_NO_INTR(payload_size = recv(sock_fd_, buf + kH4HeaderSize + kHciScoHeaderSize, hci_sco_data_total_length, 0));
      ASSERT_LOG(payload_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(payload_size == hci_sco_data_total_length, "malformed SCO packet received: size mismatch");

      HciPacket receivedHciPacket;
      receivedHciPacket.assign(buf + kH4HeaderSize, buf + kH4HeaderSize + kHciScoHeaderSize + payload_size);
      btsnoop_logger_->Capture(receivedHciPacket, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::SCO);
      {
        std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
        if (incoming_packet_callback_ == nullptr) {
          LOG_INFO("Dropping a SCO packet after processing");
          return;
        }
        incoming_packet_callback_->scoDataReceived(receivedHciPacket);
      }
    }

    if (buf[0] == kH4Iso) {
      RUN_NO_INTR(received_size = recv(sock_fd_, buf + kH4HeaderSize, kHciIsoHeaderSize, 0));
      ASSERT_LOG(received_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(received_size == kHciIsoHeaderSize, "malformed ISO header received");

      uint16_t hci_iso_data_total_length = ((buf[4] & 0x3f) << 8) + buf[3];
      int payload_size;
      RUN_NO_INTR(payload_size = recv(sock_fd_, buf + kH4HeaderSize + kHciIsoHeaderSize, hci_iso_data_total_length, 0));
      ASSERT_LOG(payload_size != -1, "Can't receive from socket: %s", strerror(errno));
      ASSERT_LOG(payload_size == hci_iso_data_total_length, "malformed ISO packet received: size mismatch");

      HciPacket receivedHciPacket;
      receivedHciPacket.assign(buf + kH4HeaderSize, buf + kH4HeaderSize + kHciIsoHeaderSize + payload_size);
      btsnoop_logger_->Capture(receivedHciPacket, SnoopLogger::Direction::INCOMING, SnoopLogger::PacketType::ISO);
      {
        std::lock_guard<std::mutex> incoming_packet_callback_lock(incoming_packet_callback_mutex_);
        if (incoming_packet_callback_ == nullptr) {
          LOG_INFO("Dropping a ISO packet after processing");
          return;
        }
        incoming_packet_callback_->isoDataReceived(receivedHciPacket);
      }
    }
    memset(buf, 0, kBufSize);
  }
};

const ModuleFactory HciHal::Factory = ModuleFactory([]() { return new HciHalHost(); });

}  // namespace hal
}  // namespace bluetooth
