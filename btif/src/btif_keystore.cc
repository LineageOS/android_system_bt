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

/* BluetoothKeystore Interface */

#include <btif_common.h>
#include <btif_keystore.h>

#include <base/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <hardware/bluetooth.h>

using base::Bind;
using base::Unretained;
using bluetooth::bluetooth_keystore::BluetoothKeystoreCallbacks;
using bluetooth::bluetooth_keystore::BluetoothKeystoreInterface;

namespace bluetooth {
namespace bluetooth_keystore {
class BluetoothKeystoreInterfaceImpl;
std::unique_ptr<BluetoothKeystoreInterface> bluetoothKeystoreInstance;

class BluetoothKeystoreInterfaceImpl
    : public bluetooth::bluetooth_keystore::BluetoothKeystoreInterface,
      public bluetooth::bluetooth_keystore::BluetoothKeystoreCallbacks {
  ~BluetoothKeystoreInterfaceImpl() override = default;

  void init(BluetoothKeystoreCallbacks* callbacks) override {
    DVLOG(2) << __func__;
    this->callbacks = callbacks;
  }

  void set_encrypt_key_or_remove_key(std::string prefix,
                                     std::string decryptedString) override {
    DVLOG(2) << __func__ << " prefix: " << prefix;

    if (!callbacks) {
      LOG(WARNING) << __func__ << " callback isn't ready. prefix: " << prefix;
      return;
    }

    do_in_jni_thread(
        base::Bind(&bluetooth::bluetooth_keystore::BluetoothKeystoreCallbacks::
                       set_encrypt_key_or_remove_key,
                   base::Unretained(callbacks), prefix, decryptedString));
  }

  std::string get_key(std::string prefix) override {
    DVLOG(2) << __func__ << " prefix: " << prefix;

    if (!callbacks) {
      LOG(WARNING) << __func__ << " callback isn't ready. prefix: " << prefix;
      return "";
    }

    return callbacks->get_key(prefix);
  }

 private:
  BluetoothKeystoreCallbacks* callbacks = nullptr;
};

BluetoothKeystoreInterface* getBluetoothKeystoreInterface() {
  if (!bluetoothKeystoreInstance) {
    bluetoothKeystoreInstance.reset(new BluetoothKeystoreInterfaceImpl());
  }

  return bluetoothKeystoreInstance.get();
}

}  // namespace bluetooth_keystore
}  // namespace bluetooth
