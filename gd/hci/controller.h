/*
 * Copyright 2019 The Android Open Source Project
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

#include "common/contextual_callback.h"
#include "hci/address.h"
#include "hci/hci_packets.h"
#include "module.h"
#include "os/handler.h"

namespace bluetooth {
namespace hci {

class Controller : public Module {
 public:
  Controller();
  virtual ~Controller();
  DISALLOW_COPY_AND_ASSIGN(Controller);

  using CompletedAclPacketsCallback =
      common::ContextualCallback<void(uint16_t /* handle */, uint16_t /* num_packets */)>;
  virtual void RegisterCompletedAclPacketsCallback(CompletedAclPacketsCallback cb);

  virtual void UnregisterCompletedAclPacketsCallback();

  virtual std::string GetLocalName() const;

  virtual LocalVersionInformation GetLocalVersionInformation() const;

  virtual bool SupportsSimplePairing() const;
  virtual bool SupportsSecureConnections() const;
  virtual bool SupportsSimultaneousLeBrEdr() const;
  virtual bool SupportsInterlacedInquiryScan() const;
  virtual bool SupportsRssiWithInquiryResults() const;
  virtual bool SupportsExtendedInquiryResponse() const;
  virtual bool SupportsRoleSwitch() const;
  virtual bool Supports3SlotPackets() const;
  virtual bool Supports5SlotPackets() const;
  virtual bool SupportsClassic2mPhy() const;
  virtual bool SupportsClassic3mPhy() const;
  virtual bool Supports3SlotEdrPackets() const;
  virtual bool Supports5SlotEdrPackets() const;
  virtual bool SupportsSco() const;
  virtual bool SupportsHv2Packets() const;
  virtual bool SupportsHv3Packets() const;
  virtual bool SupportsEv3Packets() const;
  virtual bool SupportsEv4Packets() const;
  virtual bool SupportsEv5Packets() const;
  virtual bool SupportsEsco2mPhy() const;
  virtual bool SupportsEsco3mPhy() const;
  virtual bool Supports3SlotEscoEdrPackets() const;
  virtual bool SupportsHoldMode() const;
  virtual bool SupportsSniffMode() const;
  virtual bool SupportsParkMode() const;
  virtual bool SupportsNonFlushablePb() const;
  virtual bool SupportsSniffSubrating() const;
  virtual bool SupportsEncryptionPause() const;

  virtual bool SupportsBle() const;
  virtual bool SupportsBlePrivacy() const;
  virtual bool SupportsBlePacketExtension() const;
  virtual bool SupportsBleConnectionParametersRequest() const;
  virtual bool SupportsBle2mPhy() const;
  virtual bool SupportsBleCodedPhy() const;
  virtual bool SupportsBleExtendedAdvertising() const;
  virtual bool SupportsBlePeriodicAdvertising() const;
  virtual bool SupportsBlePeripheralInitiatedFeatureExchange() const;
  virtual bool SupportsBleConnectionParameterRequest() const;
  virtual bool SupportsBlePeriodicAdvertisingSyncTransferSender() const;
  virtual bool SupportsBlePeriodicAdvertisingSyncTransferRecipient() const;
  virtual bool SupportsBleConnectedIsochronousStreamMaster() const;
  virtual bool SupportsBleConnectedIsochronousStreamSlave() const;
  virtual bool SupportsBleIsochronousBroadcaster() const;
  virtual bool SupportsBleSynchronizedReceiver() const;

  virtual uint16_t GetAclPacketLength() const;

  virtual uint16_t GetNumAclPacketBuffers() const;

  virtual uint8_t GetScoPacketLength() const;

  virtual uint16_t GetNumScoPacketBuffers() const;

  virtual Address GetMacAddress() const;

  virtual void SetEventMask(uint64_t event_mask);

  virtual void Reset();

  virtual void SetEventFilterClearAll();

  virtual void SetEventFilterInquiryResultAllDevices();

  virtual void SetEventFilterInquiryResultClassOfDevice(ClassOfDevice class_of_device,
                                                        ClassOfDevice class_of_device_mask);

  virtual void SetEventFilterInquiryResultAddress(Address address);

  virtual void SetEventFilterConnectionSetupAllDevices(AutoAcceptFlag auto_accept_flag);

  virtual void SetEventFilterConnectionSetupClassOfDevice(ClassOfDevice class_of_device,
                                                          ClassOfDevice class_of_device_mask,
                                                          AutoAcceptFlag auto_accept_flag);

  virtual void SetEventFilterConnectionSetupAddress(Address address, AutoAcceptFlag auto_accept_flag);

  virtual void WriteLocalName(std::string local_name);

  virtual void HostBufferSize(uint16_t host_acl_data_packet_length, uint8_t host_synchronous_data_packet_length,
                              uint16_t host_total_num_acl_data_packets,
                              uint16_t host_total_num_synchronous_data_packets);

  // LE controller commands
  virtual void LeSetEventMask(uint64_t le_event_mask);

  virtual LeBufferSize GetLeBufferSize() const;

  virtual uint64_t GetLeSupportedStates() const;

  virtual LeBufferSize GetControllerIsoBufferSize() const;

  virtual uint64_t GetControllerLeLocalSupportedFeatures() const;

  virtual uint8_t GetLeConnectListSize() const;

  virtual uint8_t GetLeResolvingListSize() const;

  virtual LeMaximumDataLength GetLeMaximumDataLength() const;

  virtual uint16_t GetLeMaximumAdvertisingDataLength() const;

  virtual uint16_t GetLeSuggestedDefaultDataLength() const;

  virtual uint8_t GetLeNumberOfSupportedAdverisingSets() const;

  virtual uint8_t GetLePeriodicAdvertiserListSize() const;

  virtual VendorCapabilities GetVendorCapabilities() const;

  virtual bool IsSupported(OpCode op_code) const;

  static const ModuleFactory Factory;

  static constexpr uint64_t kDefaultEventMask = 0x3dbfffffffffffff;
  static constexpr uint64_t kDefaultLeEventMask = 0x0000000000021e7f;

 protected:
  void ListDependencies(ModuleList* list) override;

  void Start() override;

  void Stop() override;

  std::string ToString() const override;

 private:
  virtual uint64_t GetLocalFeatures(uint8_t page_number) const;
  virtual uint64_t GetLocalLeFeatures() const;

  struct impl;
  std::unique_ptr<impl> impl_;
};

}  // namespace hci
}  // namespace bluetooth
