/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials provided
 *        with the distribution.
 *      * Neither the name of The Linux Foundation nor the names of its
 *        contributors may be used to endorse or promote products derived
 *        from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 *  ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 *  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *  OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 *  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *****************************************************************************/

package android.bluetooth;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.DeviceGroup;
import android.os.ParcelUuid;

import android.bluetooth.IBluetoothGroupCallback;

/**
 * API for interacting with Group Service
 * @hide
 */

interface IBluetoothDeviceGroup {
  void connect (in int appId, in BluetoothDevice device);
  void disconnect (in int appId, in BluetoothDevice device);
  void registerGroupClientApp(in ParcelUuid uuid, in IBluetoothGroupCallback callback);
  void unregisterGroupClientApp(in int appId);
  void startGroupDiscovery(in int appId, in int groupId);
  void stopGroupDiscovery(in int appId, in int groupId);
  List<DeviceGroup> getDiscoveredGroups(in boolean mPublicAddr);
  DeviceGroup getDeviceGroup(in int groupId, in boolean mPublicAddr);
  int getRemoteDeviceGroupId (in BluetoothDevice device, in ParcelUuid uuid,
                              in boolean mPublicAddr);
  boolean isGroupDiscoveryInProgress(in int groupId);
  void setExclusiveAccess(in int appId, in int groupId, in List<BluetoothDevice> devices,
                          in int value);
  void getExclusiveAccessStatus(in int appId, in int groupId, in List<BluetoothDevice> devices);
}
