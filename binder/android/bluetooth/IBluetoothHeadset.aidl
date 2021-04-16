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

import android.bluetooth.BluetoothDevice;

/**
 * API for Bluetooth Headset service
 *
 * Note before adding anything new:
 *   Internal interactions within com.android.bluetooth should be handled through
 *   HeadsetService directly instead of going through binder
 *
 * {@hide}
 */
interface IBluetoothHeadset {
    // Public API
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    List<BluetoothDevice> getConnectedDevices();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    List<BluetoothDevice> getDevicesMatchingConnectionStates(in int[] states);
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getConnectionState(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean startVoiceRecognition(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean stopVoiceRecognition(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean isAudioConnected(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean sendVendorSpecificResultCode(in BluetoothDevice device,
                                         in String command,
                                         in String arg);

    // Hidden API
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean connect(in BluetoothDevice device);
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean disconnect(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean setConnectionPolicy(in BluetoothDevice device, int connectionPolicy);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_PRIVILEGED)")
    int getConnectionPolicy(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getAudioState(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean isAudioOn();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean connectAudio();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean disconnectAudio();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void setAudioRouteAllowed(boolean allowed);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean getAudioRouteAllowed();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void setForceScoAudio(boolean forced);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean startScoUsingVirtualVoiceCall();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean stopScoUsingVirtualVoiceCall();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    oneway void phoneStateChanged(int numActive, int numHeld, int callState, String number, int type, String name);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    void clccResponse(int index, int direction, int status, int mode, boolean mpty,
                      String number, int type);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean setActiveDevice(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    BluetoothDevice getActiveDevice();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean isInbandRingingEnabled();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean setPriority(in BluetoothDevice device, int connectionPolicy);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getPriority(in BluetoothDevice device);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean isNoiseReductionSupported(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean isVoiceRecognitionSupported(in BluetoothDevice device);
}
