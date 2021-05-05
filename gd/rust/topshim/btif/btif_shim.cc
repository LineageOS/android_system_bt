/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "gd/rust/topshim/btif/btif_shim.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "btcore/include/hal_util.h"
#include "include/hardware/bluetooth.h"
#include "rust/cxx.h"
#include "src/btif.rs.h"

namespace bluetooth {
namespace topshim {
namespace rust {
namespace internal {
// We need a global pointer to the Bluetooth interface because callbacks don't
// pass back a pointer to the interface object. As a consequence, attempting to
// initialize the interface multiple times should cause an abort.
static BluetoothIntf* g_btif;

namespace rusty = ::bluetooth::topshim::rust;

static ::rust::Vec<BtProperty> prop_to_vec(int num_properties, bt_property_t* properties) {
  ::rust::Vec<BtProperty> rust_properties;

  for (int i = 0; i < num_properties; ++i) {
    ::rust::Vec<::rust::u8> val;
    val.reserve(properties[i].len);

    ::rust::u8* p = static_cast<::rust::u8*>(properties[i].val);
    for (int j = 0; j < properties[i].len; ++j) {
      val.push_back(p[j]);
    }

    BtProperty prop = {.prop_type = properties[i].type, .len = properties[i].len, .val = std::move(val)};
    rust_properties.push_back(std::move(prop));
  }

  return rust_properties;
}

static RustRawAddress to_rust_address(RawAddress* address) {
  RustRawAddress raddr;
  std::copy(std::begin(address->address), std::end(address->address), std::begin(raddr.address));

  return raddr;
}

static RawAddress from_rust_address(const RustRawAddress& address) {
  RawAddress r;
  r.FromOctets(address.address.data());

  return r;
}

static ::rust::String bdname_to_string(bt_bdname_t* bdname) {
  if (!bdname) {
    return std::string("");
  }

  return std::string(reinterpret_cast<const char*>(bdname->name));
}

static void adapter_state_changed_cb(bt_state_t state) {
  rusty::adapter_state_changed_callback(*g_btif->GetCallbacks(), state);
}

static void adapter_properties_cb(bt_status_t status, int num_properties, bt_property_t* properties) {
  rusty::adapter_properties_callback(
      *g_btif->GetCallbacks(), status, num_properties, prop_to_vec(num_properties, properties));
}

static void remote_device_properties_cb(
    bt_status_t status, RawAddress* bd_addr, int num_properties, bt_property_t* properties) {
  RustRawAddress addr = to_rust_address(bd_addr);

  rusty::remote_device_properties_callback(
      *g_btif->GetCallbacks(), status, addr, num_properties, prop_to_vec(num_properties, properties));
}

static void device_found_cb(int num_properties, bt_property_t* properties) {
  rusty::device_found_callback(*g_btif->GetCallbacks(), num_properties, prop_to_vec(num_properties, properties));
}

static void discovery_state_changed_cb(bt_discovery_state_t state) {
  rusty::discovery_state_changed_callback(*g_btif->GetCallbacks(), state);
}

static void pin_request_cb(RawAddress* remote_bd_addr, bt_bdname_t* bd_name, uint32_t cod, bool min_16_digit) {
  RustRawAddress addr = to_rust_address(remote_bd_addr);
  auto name = bdname_to_string(bd_name);

  rusty::pin_request_callback(*g_btif->GetCallbacks(), addr, name, cod, min_16_digit);
}

static void ssp_request_cb(
    RawAddress* remote_bd_addr,
    bt_bdname_t* bd_name,
    uint32_t cod,
    bt_ssp_variant_t pairing_variant,
    uint32_t pass_key) {
  RustRawAddress addr = to_rust_address(remote_bd_addr);
  auto name = bdname_to_string(bd_name);

  rusty::ssp_request_callback(*g_btif->GetCallbacks(), addr, name, cod, pairing_variant, pass_key);
}

static void bond_state_changed_cb(bt_status_t status, RawAddress* remote_bd_addr, bt_bond_state_t state) {
  RustRawAddress addr = to_rust_address(remote_bd_addr);

  rust::bond_state_changed_callback(*g_btif->GetCallbacks(), status, addr, state);
}

static void acl_state_changed_cb(
    bt_status_t status, RawAddress* remote_bd_addr, bt_acl_state_t state, bt_hci_error_code_t hci_reason) {
  RustRawAddress addr = to_rust_address(remote_bd_addr);

  rust::acl_state_changed_callback(*g_btif->GetCallbacks(), status, addr, state, hci_reason);
}

// TODO(abps) - Implement remaining callbacks

static void thread_event_cb(bt_cb_thread_evt evt) {}

static void dut_mode_recv_cb(uint16_t opcode, uint8_t* buf, uint8_t len) {}

static void le_test_mode_cb(bt_status_t status, uint16_t num_packets) {}

static void energy_info_cb(bt_activity_energy_info* energy_info, bt_uid_traffic_t* uid_data) {}

bt_callbacks_t g_callbacks = {
    sizeof(bt_callbacks_t),
    adapter_state_changed_cb,
    adapter_properties_cb,
    remote_device_properties_cb,
    device_found_cb,
    discovery_state_changed_cb,
    pin_request_cb,
    ssp_request_cb,
    bond_state_changed_cb,
    acl_state_changed_cb,
    thread_event_cb,
    dut_mode_recv_cb,
    le_test_mode_cb,
    energy_info_cb,
};
}  // namespace internal

// Bluetooth interface handler
BluetoothIntf::BluetoothIntf() : init_(false) {}

BluetoothIntf::~BluetoothIntf() {
  // We made a copy of flags from initFlags; clean them up here
  if (flags_) {
    int i = 0;
    for (const char* flag = flags_[i]; flags_[i] != nullptr; ++i) {
      std::free(const_cast<void*>(static_cast<const void*>(flag)));
    }

    std::free(const_cast<void*>(static_cast<const void*>(flags_)));
  }
}

void BluetoothIntf::ConvertFlags(::rust::Vec<::rust::String>& initFlags) {
  // Allocate number of flags + 1 (last entry must be null to signify end)
  // Must be calloc so our cleanup correctly frees everything
  flags_ = static_cast<const char**>(std::calloc(initFlags.size() + 1, sizeof(char*)));
  if (!flags_) return;

  for (int i = 0; i < initFlags.size(); ++i) {
    flags_[i] = strndup(initFlags[i].data(), initFlags[i].size());
    if (!flags_) {
      return;
    }
  }
}

bool BluetoothIntf::Initialize(::rust::Box<RustCallbacks> callbacks, ::rust::Vec<::rust::String> initFlags) {
  if (init_) return true;

  callbacks_ = std::make_unique<::rust::Box<RustCallbacks>>(std::move(callbacks));
  ConvertFlags(initFlags);

  if (!hal_util_load_bt_library(&intf_)) {
    int ret = intf_->init(
        &internal::g_callbacks,
        false,  // guest_mode,
        false,  // is_niap_mode,
        0,      // config_compare_result,
        flags_,
        false  // is_atv
    );

    // We only accept SUCCESS and not BT_STATUS_DONE. If some other interface
    // has already been registered, that means our callbacks won't be called and
    // that is problematic.
    init_ = ret == BT_STATUS_SUCCESS;
  }

  return init_;
}

void BluetoothIntf::CleanUp() const {
  intf_->cleanup();
}

int BluetoothIntf::Enable() const {
  return intf_->enable();
}

int BluetoothIntf::Disable() const {
  return intf_->disable();
}

int BluetoothIntf::GetAdapterProperties() const {
  return intf_->get_adapter_properties();
}

int BluetoothIntf::GetAdapterProperty(int prop) const {
  return intf_->get_adapter_property(static_cast<bt_property_type_t>(prop));
}

static bt_property_t convert_to_cprop(const BtProperty& prop) {
  bt_property_t c_prop = {
      .type = static_cast<bt_property_type_t>(prop.prop_type),
      .len = prop.len,
      .val = reinterpret_cast<void*>(const_cast<unsigned char*>(prop.val.data())),
  };

  return c_prop;
}

int BluetoothIntf::SetAdapterProperty(const BtProperty& prop) const {
  bt_property_t c_prop = convert_to_cprop(prop);
  return intf_->set_adapter_property(&c_prop);
}

int BluetoothIntf::GetRemoteDeviceProperties(const RustRawAddress& address) const {
  RawAddress addr = internal::from_rust_address(address);

  return intf_->get_remote_device_properties(&addr);
}

int BluetoothIntf::GetRemoteDeviceProperty(const RustRawAddress& address, int prop_type) const {
  RawAddress addr = internal::from_rust_address(address);
  return intf_->get_remote_device_property(&addr, static_cast<bt_property_type_t>(prop_type));
}

int BluetoothIntf::SetRemoteDeviceProperty(const RustRawAddress& address, const BtProperty& prop) const {
  RawAddress addr = internal::from_rust_address(address);

  bt_property_t c_prop = convert_to_cprop(prop);
  return intf_->set_remote_device_property(&addr, &c_prop);
}

int BluetoothIntf::GetRemoteServices(const RustRawAddress& address) const {
  RawAddress addr = internal::from_rust_address(address);

  return intf_->get_remote_services(&addr);
}

int BluetoothIntf::StartDiscovery() const {
  return intf_->start_discovery();
}

int BluetoothIntf::CancelDiscovery() const {
  return intf_->cancel_discovery();
}

int BluetoothIntf::CreateBond(const RustRawAddress& address, int transport) const {
  RawAddress addr = internal::from_rust_address(address);

  return intf_->create_bond(&addr, transport);
}

int BluetoothIntf::RemoveBond(const RustRawAddress& address) const {
  RawAddress addr = internal::from_rust_address(address);

  return intf_->remove_bond(&addr);
}

int BluetoothIntf::CancelBond(const RustRawAddress& address) const {
  RawAddress addr = internal::from_rust_address(address);

  return intf_->cancel_bond(&addr);
}

int BluetoothIntf::GetConnectionState(const RustRawAddress& address) const {
  RawAddress addr = internal::from_rust_address(address);

  return intf_->get_connection_state(&addr);
}

int BluetoothIntf::PinReply(
    const RustRawAddress& address, uint8_t accept, uint8_t pin_len, const BtPinCode& code) const {
  RawAddress addr = internal::from_rust_address(address);

  bt_pin_code_t pin_code;
  std::copy(std::begin(code.pin), std::end(code.pin), pin_code.pin);

  return intf_->pin_reply(&addr, accept, pin_len, &pin_code);
}

int BluetoothIntf::SspReply(const RustRawAddress& address, int ssp_variant, uint8_t accept, uint32_t passkey) const {
  RawAddress addr = internal::from_rust_address(address);

  return intf_->ssp_reply(&addr, static_cast<bt_ssp_variant_t>(ssp_variant), accept, passkey);
}

std::unique_ptr<BluetoothIntf> Load() {
  // Don't allow the bluetooth interface to be allocated twice
  if (internal::g_btif) std::abort();

  auto btif = std::make_unique<BluetoothIntf>();
  internal::g_btif = btif.get();
  return btif;
}

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth
