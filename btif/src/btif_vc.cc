/*
 * Copyright 2021 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

/* Volume Control Interface */

#include <hardware/bluetooth.h>
#include <hardware/bt_vc.h>

#include <base/bind.h>
#include <base/location.h>
#include <base/logging.h>

#include "bta_vc_api.h"
#include "btif_common.h"
#include "stack/include/btu.h"

using base::Bind;
using base::Unretained;
using bluetooth::vc::ConnectionState;
using bluetooth::vc::VolumeControlCallbacks;
using bluetooth::vc::VolumeControlInterface;

namespace {
std::unique_ptr<VolumeControlInterface> vc_instance;

class VolumeControlInterfaceImpl : public VolumeControlInterface,
                                   public VolumeControlCallbacks {
  ~VolumeControlInterfaceImpl() override = default;

  void Init(VolumeControlCallbacks* callbacks) override {
    DVLOG(2) << __func__;
    this->callbacks_ = callbacks;
    do_in_main_thread(FROM_HERE, Bind(&VolumeControl::Initialize, this));
  }

  void OnConnectionState(ConnectionState state,
                         const RawAddress& address) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_jni_thread(FROM_HERE, Bind(&VolumeControlCallbacks::OnConnectionState,
                                     Unretained(callbacks_), state, address));
  }

  void OnVolumeStateChanged(const RawAddress& address, uint8_t volume,
                            bool mute) override {
    DVLOG(2) << __func__ << " address: " << address << "volume: " << volume
             << "mute: " << mute;
    do_in_jni_thread(FROM_HERE,
                     Bind(&VolumeControlCallbacks::OnVolumeStateChanged,
                          Unretained(callbacks_), address, volume, mute));
  }

  void OnGroupVolumeStateChanged(int group_id, uint8_t volume,
                                 bool mute) override {
    DVLOG(2) << __func__ << "group_id: " << group_id << "volume: " << volume
             << "mute: " << mute;
    do_in_jni_thread(FROM_HERE,
                     Bind(&VolumeControlCallbacks::OnGroupVolumeStateChanged,
                          Unretained(callbacks_), group_id, volume, mute));
  }

  void Connect(const RawAddress& address) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_main_thread(FROM_HERE,
                      Bind(&VolumeControl::Connect,
                           Unretained(VolumeControl::Get()), address));
  }

  void Disconnect(const RawAddress& address) override {
    DVLOG(2) << __func__ << " address: " << address;
    do_in_main_thread(FROM_HERE,
                      Bind(&VolumeControl::Disconnect,
                           Unretained(VolumeControl::Get()), address));
  }

  void SetVolume(std::variant<RawAddress, int> addr_or_group_id,
                 uint8_t volume) override {
    DVLOG(2) << __func__ << " volume: " << volume;
    do_in_main_thread(FROM_HERE, Bind(&VolumeControl::SetVolume,
                                      Unretained(VolumeControl::Get()),
                                      std::move(addr_or_group_id), volume));
  }

  void RemoveDevice(const RawAddress& address) override {
    DVLOG(2) << __func__ << " address: " << address;

    /* RemoveDevice can be called on devices that don't have HA enabled */
    if (VolumeControl::IsVolumeControlRunning()) {
      do_in_main_thread(FROM_HERE,
                        Bind(&VolumeControl::Disconnect,
                             Unretained(VolumeControl::Get()), address));
    }

    /* Placeholder: Remove things from storage here */
  }

  void Cleanup(void) override {
    DVLOG(2) << __func__;
    do_in_main_thread(FROM_HERE, Bind(&VolumeControl::CleanUp));
  }

 private:
  VolumeControlCallbacks* callbacks_;
};

} /* namespace */

VolumeControlInterface* btif_volume_control_get_interface(void) {
  if (!vc_instance) vc_instance.reset(new VolumeControlInterfaceImpl());

  return vc_instance.get();
}
