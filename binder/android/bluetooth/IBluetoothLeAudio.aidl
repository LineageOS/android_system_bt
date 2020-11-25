/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com.
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

package android.bluetooth;

import android.bluetooth.BluetoothDevice;

/**
 * APIs for Bluetooth LE Audio service
 *
 * @hide
 */
interface IBluetoothLeAudio {
    // Public API
    boolean connect(in BluetoothDevice device);
    boolean disconnect(in BluetoothDevice device);
    List<BluetoothDevice> getConnectedDevices();
    List<BluetoothDevice> getDevicesMatchingConnectionStates(in int[] states);
    int getConnectionState(in BluetoothDevice device);
    boolean setActiveDevice(in BluetoothDevice device);
    List<BluetoothDevice> getActiveDevices();
    boolean setConnectionPolicy(in BluetoothDevice device, int connectionPolicy);
    int getConnectionPolicy(in BluetoothDevice device);

    const int LE_AUDIO_GROUP_ID_INVALID = -1;

    /**
     * Get device group id. Devices with same group id belong to same group (i.e left and right
     * earbud)
     */
    int getGroupId(in BluetoothDevice device);

}
