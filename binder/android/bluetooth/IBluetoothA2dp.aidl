/*
 * Copyright 2008 The Android Open Source Project
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

import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothCodecStatus;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BufferConstraints;

/**
 * APIs for Bluetooth A2DP service
 *
 * @hide
 */
interface IBluetoothA2dp {
    // Public API
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean connect(in BluetoothDevice device);
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean disconnect(in BluetoothDevice device);
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    List<BluetoothDevice> getConnectedDevices();
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    List<BluetoothDevice> getDevicesMatchingConnectionStates(in int[] states);
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getConnectionState(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean setActiveDevice(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    BluetoothDevice getActiveDevice();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setConnectionPolicy(in BluetoothDevice device, int connectionPolicy);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
    int getConnectionPolicy(in BluetoothDevice device);
    boolean isAvrcpAbsoluteVolumeSupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    oneway void setAvrcpAbsoluteVolume(int volume);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean isA2dpPlaying(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    BluetoothCodecStatus getCodecStatus(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    oneway void setCodecConfigPreference(in BluetoothDevice device,
                in BluetoothCodecConfig codecConfig);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    oneway void enableOptionalCodecs(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    oneway void disableOptionalCodecs(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int supportsOptionalCodecs(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getOptionalCodecsEnabled(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    oneway void setOptionalCodecsEnabled(in BluetoothDevice device, int value);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
    int getDynamicBufferSupport();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
    BufferConstraints getBufferConstraints();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
    boolean setBufferLengthMillis(int codec, int size);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getPriority(in BluetoothDevice device);
}
