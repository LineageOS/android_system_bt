/*
 * Copyright 2021 The Android Open Source Project
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
#pragma once

#include <cstdint>

#include "common/contextual_callback.h"
#include "hci/address.h"
#include "hci/controller.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"

#include <gmock/gmock.h>

// Unit test interfaces
namespace bluetooth {
namespace hci {
namespace testing {

class MockController : public Controller {
 public:
  MOCK_METHOD(void, RegisterCompletedAclPacketsCallback, (CompletedAclPacketsCallback cb));
  MOCK_METHOD(void, UnregisterCompletedAclPacketsCallback, ());
  MOCK_METHOD(void, RegisterCompletedMonitorAclPacketsCallback, (CompletedAclPacketsCallback cb));
  MOCK_METHOD(void, UnregisterCompletedMonitorAclPacketsCallback, ());
  MOCK_METHOD(std::string, GetLocalName, (), (const));
  MOCK_METHOD(LocalVersionInformation, GetLocalVersionInformation, (), (const));
  MOCK_METHOD(bool, SupportsSimplePairing, (), (const));
  MOCK_METHOD(bool, SupportsSecureConnections, (), (const));
  MOCK_METHOD(bool, SupportsSimultaneousLeBrEdr, (), (const));
  MOCK_METHOD(bool, SupportsInterlacedInquiryScan, (), (const));
  MOCK_METHOD(bool, SupportsRssiWithInquiryResults, (), (const));
  MOCK_METHOD(bool, SupportsExtendedInquiryResponse, (), (const));
  MOCK_METHOD(bool, SupportsRoleSwitch, (), (const));
  MOCK_METHOD(bool, Supports3SlotPackets, (), (const));
  MOCK_METHOD(bool, Supports5SlotPackets, (), (const));
  MOCK_METHOD(bool, SupportsClassic2mPhy, (), (const));
  MOCK_METHOD(bool, SupportsClassic3mPhy, (), (const));
  MOCK_METHOD(bool, Supports3SlotEdrPackets, (), (const));
  MOCK_METHOD(bool, Supports5SlotEdrPackets, (), (const));
  MOCK_METHOD(bool, SupportsSco, (), (const));
  MOCK_METHOD(bool, SupportsHv2Packets, (), (const));
  MOCK_METHOD(bool, SupportsHv3Packets, (), (const));
  MOCK_METHOD(bool, SupportsEv3Packets, (), (const));
  MOCK_METHOD(bool, SupportsEv4Packets, (), (const));
  MOCK_METHOD(bool, SupportsEv5Packets, (), (const));
  MOCK_METHOD(bool, SupportsEsco2mPhy, (), (const));
  MOCK_METHOD(bool, SupportsEsco3mPhy, (), (const));
  MOCK_METHOD(bool, Supports3SlotEscoEdrPackets, (), (const));
  MOCK_METHOD(bool, SupportsHoldMode, (), (const));
  MOCK_METHOD(bool, SupportsSniffMode, (), (const));
  MOCK_METHOD(bool, SupportsParkMode, (), (const));
  MOCK_METHOD(bool, SupportsNonFlushablePb, (), (const));
  MOCK_METHOD(bool, SupportsSniffSubrating, (), (const));
  MOCK_METHOD(bool, SupportsEncryptionPause, (), (const));
  MOCK_METHOD(bool, SupportsBle, (), (const));
  MOCK_METHOD(bool, SupportsBlePrivacy, (), (const));
  MOCK_METHOD(bool, SupportsBlePacketExtension, (), (const));
  MOCK_METHOD(bool, SupportsBleConnectionParametersRequest, (), (const));
  MOCK_METHOD(bool, SupportsBle2mPhy, (), (const));
  MOCK_METHOD(bool, SupportsBleCodedPhy, (), (const));
  MOCK_METHOD(bool, SupportsBleExtendedAdvertising, (), (const));
  MOCK_METHOD(bool, SupportsBlePeriodicAdvertising, (), (const));
  MOCK_METHOD(bool, SupportsBlePeripheralInitiatedFeatureExchange, (), (const));
  MOCK_METHOD(bool, SupportsBleConnectionParameterRequest, (), (const));
  MOCK_METHOD(bool, SupportsBlePeriodicAdvertisingSyncTransferSender, (), (const));
  MOCK_METHOD(bool, SupportsBlePeriodicAdvertisingSyncTransferRecipient, (), (const));
  MOCK_METHOD(bool, SupportsBleConnectedIsochronousStreamCentral, (), (const));
  MOCK_METHOD(bool, SupportsBleConnectedIsochronousStreamPeripheral, (), (const));
  MOCK_METHOD(bool, SupportsBleIsochronousBroadcaster, (), (const));
  MOCK_METHOD(bool, SupportsBleSynchronizedReceiver, (), (const));
  MOCK_METHOD(uint16_t, GetAclPacketLength, (), (const));
  MOCK_METHOD(uint16_t, GetNumAclPacketBuffers, (), (const));
  MOCK_METHOD(uint8_t, GetScoPacketLength, (), (const));
  MOCK_METHOD(uint16_t, GetNumScoPacketBuffers, (), (const));
  MOCK_METHOD(Address, GetMacAddress, (), (const));
  MOCK_METHOD(void, SetEventMask, (uint64_t event_mask));
  MOCK_METHOD(void, Reset, ());
  MOCK_METHOD(void, SetEventFilterClearAll, ());
  MOCK_METHOD(void, SetEventFilterInquiryResultAllDevices, ());
  MOCK_METHOD(
      void,
      SetEventFilterInquiryResultClassOfDevice,
      (ClassOfDevice class_of_device, ClassOfDevice class_of_device_mask));
  MOCK_METHOD(void, SetEventFilterInquiryResultAddress, (Address address));
  MOCK_METHOD(void, SetEventFilterConnectionSetupAllDevices, (AutoAcceptFlag auto_accept_flag));
  MOCK_METHOD(
      void,
      SetEventFilterConnectionSetupClassOfDevice,
      (ClassOfDevice class_of_device, ClassOfDevice class_of_device_mask, AutoAcceptFlag auto_accept_flag));
  MOCK_METHOD(void, SetEventFilterConnectionSetupAddress, (Address address, AutoAcceptFlag auto_accept_flag));
  MOCK_METHOD(void, WriteLocalName, (std::string local_name));
  MOCK_METHOD(
      void,
      HostBufferSize,
      (uint16_t host_acl_data_packet_length,
       uint8_t host_synchronous_data_packet_length,
       uint16_t host_total_num_acl_data_packets,
       uint16_t host_total_num_synchronous_data_packets));
  // LE controller commands
  MOCK_METHOD(void, LeSetEventMask, (uint64_t le_event_mask));
  MOCK_METHOD(LeBufferSize, GetLeBufferSize, (), (const));
  MOCK_METHOD(uint64_t, GetLeSupportedStates, (), (const));
  MOCK_METHOD(LeBufferSize, GetControllerIsoBufferSize, (), (const));
  MOCK_METHOD(uint64_t, GetControllerLeLocalSupportedFeatures, (), (const));
  MOCK_METHOD(uint8_t, GetLeConnectListSize, (), (const));
  MOCK_METHOD(uint8_t, GetLeResolvingListSize, (), (const));
  MOCK_METHOD(LeMaximumDataLength, GetLeMaximumDataLength, (), (const));
  MOCK_METHOD(uint16_t, GetLeMaximumAdvertisingDataLength, (), (const));
  MOCK_METHOD(uint16_t, GetLeSuggestedDefaultDataLength, (), (const));
  MOCK_METHOD(uint8_t, GetLeNumberOfSupportedAdverisingSets, (), (const));
  MOCK_METHOD(uint8_t, GetLePeriodicAdvertiserListSize, (), (const));
  MOCK_METHOD(VendorCapabilities, GetVendorCapabilities, (), (const));
  MOCK_METHOD(bool, IsSupported, (OpCode op_code), (const));
};

}  // namespace testing
}  // namespace hci
}  // namespace bluetooth
