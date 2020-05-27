/*
 * Copyright 2013 The Android Open Source Project
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

import android.app.PendingIntent;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertisingSetParameters;
import android.bluetooth.le.PeriodicAdvertisingParameters;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.bluetooth.le.ResultStorageDescriptor;
import android.content.AttributionSource;
import android.os.ParcelUuid;
import android.os.WorkSource;

import android.bluetooth.IBluetoothGattCallback;
import android.bluetooth.IBluetoothGattServerCallback;
import android.bluetooth.le.IAdvertisingSetCallback;
import android.bluetooth.le.IPeriodicAdvertisingCallback;
import android.bluetooth.le.IScannerCallback;

/**
 * API for interacting with BLE / GATT
 * @hide
 */
interface IBluetoothGatt {
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    List<BluetoothDevice> getDevicesMatchingConnectionStates(in int[] states, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void registerScanner(in IScannerCallback callback, in WorkSource workSource, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void unregisterScanner(in int scannerId, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void startScan(in int scannerId, in ScanSettings settings, in List<ScanFilter> filters,
                   in List scanStorages, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void startScanForIntent(in PendingIntent intent, in ScanSettings settings, in List<ScanFilter> filters,
                            in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void stopScanForIntent(in PendingIntent intent, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void stopScan(in int scannerId, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void flushPendingBatchResults(in int scannerId, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void startAdvertisingSet(in AdvertisingSetParameters parameters, in AdvertiseData advertiseData,
                                in AdvertiseData scanResponse, in PeriodicAdvertisingParameters periodicParameters,
                                in AdvertiseData periodicData, in int duration, in int maxExtAdvEvents,
                                in IAdvertisingSetCallback callback, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void stopAdvertisingSet(in IAdvertisingSetCallback callback, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(allOf={android.Manifest.permission.BLUETOOTH_ADVERTISE,android.Manifest.permission.BLUETOOTH_PRIVILEGED})")
    void getOwnAddress(in int advertiserId, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void enableAdvertisingSet(in int advertiserId, in boolean enable, in int duration, in int maxExtAdvEvents, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void setAdvertisingData(in int advertiserId, in AdvertiseData data, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void setScanResponseData(in int advertiserId, in AdvertiseData data, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void setAdvertisingParameters(in int advertiserId, in AdvertisingSetParameters parameters, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void setPeriodicAdvertisingParameters(in int advertiserId, in PeriodicAdvertisingParameters parameters, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void setPeriodicAdvertisingData(in int advertiserId, in AdvertiseData data, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE)")
    void setPeriodicAdvertisingEnable(in int advertiserId, in boolean enable, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void registerSync(in ScanResult scanResult, in int skip, in int timeout, in IPeriodicAdvertisingCallback callback, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_SCAN)")
    void unregisterSync(in IPeriodicAdvertisingCallback callback, in AttributionSource attributionSource);
    void transferSync(in BluetoothDevice bda, in int serviceData, in int syncHandle);
    void transferSetInfo(in BluetoothDevice bda, in int serviceData, in int advertisingHandle, in IPeriodicAdvertisingCallback callback);

    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void registerClient(in ParcelUuid appId, in IBluetoothGattCallback callback, boolean eatt_support, in AttributionSource attributionSource);

    @UnsupportedAppUsage
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void unregisterClient(in int clientIf, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void clientConnect(in int clientIf, in String address, in boolean isDirect, in int transport, in boolean opportunistic, in int phy, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void clientDisconnect(in int clientIf, in String address, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void clientSetPreferredPhy(in int clientIf, in String address, in int txPhy, in int rxPhy, in int phyOptions, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void clientReadPhy(in int clientIf, in String addres, in AttributionSource attributionSources);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void refreshDevice(in int clientIf, in String address, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void discoverServices(in int clientIf, in String address, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void discoverServiceByUuid(in int clientIf, in String address, in ParcelUuid uuid, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void readCharacteristic(in int clientIf, in String address, in int handle, in int authReq, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void readUsingCharacteristicUuid(in int clientIf, in String address, in ParcelUuid uuid,
                           in int startHandle, in int endHandle, in int authReq, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void writeCharacteristic(in int clientIf, in String address, in int handle,
                            in int writeType, in int authReq, in byte[] value, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void readDescriptor(in int clientIf, in String address, in int handle, in int authReq, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void writeDescriptor(in int clientIf, in String address, in int handle,
                            in int authReq, in byte[] value, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void registerForNotification(in int clientIf, in String address, in int handle, in boolean enable, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void beginReliableWrite(in int clientIf, in String address, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void endReliableWrite(in int clientIf, in String address, in boolean execute, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void readRemoteRssi(in int clientIf, in String address, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void configureMTU(in int clientIf, in String address, in int mtu, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void connectionParameterUpdate(in int clientIf, in String address, in int connectionPriority, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void leConnectionUpdate(int clientIf, String address, int minInterval,
                            int maxInterval, int peripheralLatency, int supervisionTimeout,
                            int minConnectionEventLen, int maxConnectionEventLen, in AttributionSource attributionSource);

    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void registerServer(in ParcelUuid appId, in IBluetoothGattServerCallback callback, boolean eatt_support, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void unregisterServer(in int serverIf, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void serverConnect(in int serverIf, in String address, in boolean isDirect, in int transport, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void serverDisconnect(in int serverIf, in String address, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void serverSetPreferredPhy(in int clientIf, in String address, in int txPhy, in int rxPhy, in int phyOptions, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void serverReadPhy(in int clientIf, in String address, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void addService(in int serverIf, in BluetoothGattService service, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void removeService(in int serverIf, in int handle, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void clearServices(in int serverIf, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void sendResponse(in int serverIf, in String address, in int requestId,
                            in int status, in int offset, in byte[] value, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void sendNotification(in int serverIf, in String address, in int handle,
                            in boolean confirm, in byte[] value, in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void disconnectAll(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    void unregAll(in AttributionSource attributionSource);
    @JavaPassthrough(annotation="@android.annotation.RequiresPermission(android.Manifest.permission.BLUETOOTH_CONNECT)")
    int numHwTrackFiltersAvailable(in AttributionSource attributionSource);
}
