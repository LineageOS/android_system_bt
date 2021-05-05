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
#ifndef GD_RUST_TOPSHIM_BTIF_BTIF_SHIM_H
#define GD_RUST_TOPSHIM_BTIF_BTIF_SHIM_H

#include <memory>

#include "include/hardware/bluetooth.h"
#include "rust/cxx.h"

namespace bluetooth {
namespace topshim {
namespace rust {

struct RustCallbacks;
struct InitParams;
struct RustRawAddress;
struct BtProperty;
struct BtPinCode;
struct BtUuid;

class BluetoothIntf {
 public:
  BluetoothIntf();
  ~BluetoothIntf();

  bool Initialize(::rust::Box<RustCallbacks> callbacks, ::rust::Vec<::rust::String> initFlags);
  void CleanUp() const;

  int Enable() const;
  int Disable() const;

  int GetAdapterProperties() const;
  int GetAdapterProperty(int prop_type) const;
  int SetAdapterProperty(const BtProperty& prop) const;

  int GetRemoteDeviceProperties(const RustRawAddress& address) const;
  int GetRemoteDeviceProperty(const RustRawAddress& address, int prop_type) const;
  int SetRemoteDeviceProperty(const RustRawAddress& address, const BtProperty& prop) const;

  int GetRemoteServices(const RustRawAddress& address) const;

  int StartDiscovery() const;
  int CancelDiscovery() const;

  int CreateBond(const RustRawAddress& address, int transport) const;
  int RemoveBond(const RustRawAddress& address) const;
  int CancelBond(const RustRawAddress& address) const;

  int GetConnectionState(const RustRawAddress& address) const;

  int PinReply(const RustRawAddress& address, uint8_t accept, uint8_t pin_len, const BtPinCode& code) const;
  int SspReply(const RustRawAddress& address, int ssp_variant, uint8_t accept, uint32_t passkey) const;

  ::rust::Box<RustCallbacks>& GetCallbacks() {
    return *callbacks_;
  }

 private:
  void ConvertFlags(::rust::Vec<::rust::String>& flags);

  std::unique_ptr<::rust::Box<RustCallbacks>> callbacks_;
  bool init_;
  const char** flags_;
  const bt_interface_t* intf_;
};

std::unique_ptr<BluetoothIntf> Load();

}  // namespace rust
}  // namespace topshim
}  // namespace bluetooth

#endif  // GD_RUST_TOPSHIM_BTIF_BTIF_SHIM_H
