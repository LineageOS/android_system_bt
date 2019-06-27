/*
 * Copyright (C) 2018, The Linux Foundation. All rights reserved.
 * Not a Contribution.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the
 * disclaimer below) provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * * Neither the name of The Linux Foundation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
 * GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.bluetooth;

import android.bluetooth.IBluetoothCallback;
import android.bluetooth.IBluetoothConnectionCallback;
import android.bluetooth.IBluetoothMetadataListener;
import android.bluetooth.IBluetoothOobDataCallback;
import android.bluetooth.IBluetoothSocketManager;
import android.bluetooth.IBluetoothStateChangeCallback;
import android.bluetooth.BluetoothActivityEnergyInfo;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.OobData;
import android.content.AttributionSource;
import android.os.ParcelUuid;
import android.os.ParcelFileDescriptor;
import android.os.ResultReceiver;

/**
 * System private API for talking with the Bluetooth service.
 *
 * {@hide}
 */
interface IBluetooth
{
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    int getState();

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean enable(boolean quietMode, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean disable(in AttributionSource attributionSource);

    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.LOCAL_MAC_ADDRESS})")
    String getAddress();
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.LOCAL_MAC_ADDRESS})")
    String getAddressWithAttribution(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    ParcelUuid[] getUuids(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean setName(in String name, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    String getName(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    int getNameLengthForAdvertise(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    BluetoothClass getBluetoothClass(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setBluetoothClass(in BluetoothClass bluetoothClass, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getIoCapability(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setIoCapability(int capability, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getLeIoCapability(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setLeIoCapability(int capability, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    int getScanMode(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    boolean setScanMode(int mode, int duration, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    int getDiscoverableTimeout(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    boolean setDiscoverableTimeout(int timeout, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    boolean startDiscovery(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    boolean cancelDiscovery(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    boolean isDiscovering(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    long getDiscoveryEndMillis(in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    int getAdapterConnectionState();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    int getProfileConnectionState(int profile);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    BluetoothDevice[] getBondedDevices(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean createBond(in BluetoothDevice device, in int transport, in OobData p192Data, in OobData p256Data, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean cancelBondProcess(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean removeBond(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getBondState(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean isBondingInitiatedLocally(in BluetoothDevice device, in AttributionSource attributionSource);
    void setBondingInitiatedLocally(in BluetoothDevice devicei, in boolean localInitiated);
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    long getSupportedProfiles();
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getConnectionState(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getConnectionStateWithAttribution(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    String getRemoteName(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getRemoteType(in BluetoothDevice device, in AttributionSource attributionSource);
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    String getRemoteAlias(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    String getRemoteAliasWithAttribution(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int setRemoteAlias(in BluetoothDevice device, in String name, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getRemoteClass(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    ParcelUuid[] getRemoteUuids(in BluetoothDevice device, in AttributionSource attributionSource);
    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean fetchRemoteUuids(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean fetchRemoteUuidsWithAttribution(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean sdpSearch(in BluetoothDevice device, in ParcelUuid uuid, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getBatteryLevel(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getMaxConnectedAudioDevices(in AttributionSource attributionSource);

    boolean isTwsPlusDevice(in BluetoothDevice device);
    String getTwsPlusPeerAddress(in BluetoothDevice device);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean setPin(in BluetoothDevice device, boolean accept, int len, in byte[] pinCode, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    boolean setPasskey(in BluetoothDevice device, boolean accept, int len, in byte[] passkey, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setPairingConfirmation(in BluetoothDevice device, boolean accept, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getPhonebookAccessPermission(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setSilenceMode(in BluetoothDevice device, boolean silence, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean getSilenceMode(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setPhonebookAccessPermission(in BluetoothDevice device, int value, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getMessageAccessPermission(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setMessageAccessPermission(in BluetoothDevice device, int value, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int getSimAccessPermission(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setSimAccessPermission(in BluetoothDevice device, int value, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    void registerCallback(in IBluetoothCallback callback, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    void unregisterCallback(in IBluetoothCallback callback, in AttributionSource attributionSource);

    // For Socket
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    IBluetoothSocketManager getSocketManager();

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean factoryReset(in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isMultiAdvertisementSupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isOffloadedFilteringSupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isOffloadedScanBatchingSupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isActivityAndEnergyReportingSupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isLe2MPhySupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isLeCodedPhySupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isLeExtendedAdvertisingSupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    boolean isLePeriodicAdvertisingSupported();
    @JavaPassthrough(annotation="@android.annotation.RequiresNoPermission")
    int getLeMaximumAdvertisingDataLength();

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    BluetoothActivityEnergyInfo reportActivityInfo(in AttributionSource attributionSource);

    // For Metadata
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean registerMetadataListener(in IBluetoothMetadataListener listener, in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean unregisterMetadataListener(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean setMetadata(in BluetoothDevice device, in int key, in byte[] value, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    byte[] getMetadata(in BluetoothDevice device, in int key, in AttributionSource attributionSource);

    /**
     * Requests the controller activity info asynchronously.
     * The implementor is expected to reply with the
     * {@link android.bluetooth.BluetoothActivityEnergyInfo} object placed into the Bundle with the
     * key {@link android.os.BatteryStats#RESULT_RECEIVER_CONTROLLER_KEY}.
     * The result code is ignored.
     */
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    oneway void requestActivityInfo(in ResultReceiver result, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    void onLeServiceUp(in AttributionSource attributionSource);
    void updateQuietModeStatus(boolean quietMode);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    void onBrEdrDown(in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean connectAllEnabledProfiles(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean disconnectAllEnabledProfiles(in BluetoothDevice device, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean setActiveDevice(in BluetoothDevice device, in int profiles, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    List<BluetoothDevice> getMostRecentlyConnectedDevices(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED,android.Manifest.permission.MODIFY_PHONE_STATE})")
    boolean removeActiveDevice(in int profiles, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean registerBluetoothConnectionCallback(in IBluetoothConnectionCallback callback, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean unregisterBluetoothConnectionCallback(in IBluetoothConnectionCallback callback, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    boolean canBondWithoutDialog(in BluetoothDevice device, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_CONNECT,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    void generateLocalOobData(in int transport, IBluetoothOobDataCallback callback, in AttributionSource attributionSource);
}
