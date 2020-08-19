/*
 *
 *  Copyright 2019 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
#include "security/record/security_record_storage.h"

#include "storage/mutation.h"

namespace bluetooth {
namespace security {
namespace record {

namespace {
void SetClassicData(
    storage::Mutation& mutation, std::shared_ptr<record::SecurityRecord> record, storage::Device& device) {
  if (*device.GetDeviceType() == hci::DeviceType::LE) {
    return;
  }
  if (record->IsClassicLinkKeyValid()) {
    LOG_WARN("Type: %d", static_cast<int>(*device.GetDeviceType()));
    mutation.Add(device.Classic().SetLinkKey(record->GetLinkKey()));
    mutation.Add(device.Classic().SetLinkKeyType(record->GetKeyType()));
  }
}

void SetLeData(storage::Mutation& mutation, std::shared_ptr<record::SecurityRecord> record, storage::Device& device) {
  if (*device.GetDeviceType() == hci::DeviceType::BR_EDR) {
    return;
  }
  if (record->identity_address_) {
    mutation.Add(device.Le().SetIdentityAddress(record->identity_address_->GetAddress()));
  }
  if (record->pseudo_address_) {
    mutation.Add(device.Le().SetLegacyPseudoAddress(record->pseudo_address_->GetAddress()));
  }
  if (record->ltk) {
    common::ByteArray<16> byte_array(*record->ltk);
    mutation.Add(device.Le().SetLtk(byte_array.ToString()));
  }
  if (record->ediv) {
    mutation.Add(device.Le().SetEdiv(*record->ediv));
  }
  if (record->rand) {
    common::ByteArray<8> byte_array(*record->rand);
    mutation.Add(device.Le().SetRand(byte_array.ToString()));
  }

  if (record->irk) {
    common::ByteArray<16> byte_array(*record->irk);
    mutation.Add(device.Le().SetIrk(byte_array.ToString()));
  }

  if (record->signature_key) {
    common::ByteArray<16> byte_array(*record->signature_key);
    mutation.Add(device.Le().SetSignatureKey(byte_array.ToString()));
  }
}

void SetAuthenticationData(storage::Mutation& mutation, std::shared_ptr<record::SecurityRecord> record, storage::Device& device) {
  device.SetIsAuthenticated((record->IsAuthenticated() ? 1 : 0));
  device.SetIsEncryptionRequired((record->IsEncryptionRequired() ? 1 : 0));
  device.SetRequiresMitmProtection(record->RequiresMitmProtection() ? 1 : 0);
}
}  // namespace

SecurityRecordStorage::SecurityRecordStorage(storage::StorageModule* storage_module, os::Handler* handler)
    : storage_module_(storage_module), handler_(handler) {}

void SecurityRecordStorage::SaveSecurityRecords(std::set<std::shared_ptr<record::SecurityRecord>>* records) {
  for (auto record : *records) {
    if (record->IsTemporary()) continue;
    storage::Device device = storage_module_->GetDeviceByClassicMacAddress(record->GetPseudoAddress()->GetAddress());
    auto mutation = storage_module_->Modify();
    mutation.Add(device.SetDeviceType(hci::DeviceType::BR_EDR));
    if (record->IsClassicLinkKeyValid() && !record->identity_address_) {
      mutation.Add(device.SetDeviceType(hci::DeviceType::BR_EDR));
    } else if (record->IsClassicLinkKeyValid() && record->identity_address_) {
      mutation.Add(device.SetDeviceType(hci::DeviceType::DUAL));
    } else if (!record->IsClassicLinkKeyValid() && record->identity_address_) {
      mutation.Add(device.SetDeviceType(hci::DeviceType::LE));
    } else {
      LOG_ERROR(
          "Cannot determine device type from security record for '%s'; dropping!",
          record->GetPseudoAddress()->ToString().c_str());
      continue;
    }
    mutation.Commit();
    SetClassicData(mutation, record, device);
    SetLeData(mutation, record, device);
    SetAuthenticationData(mutation, record, device);
    mutation.Commit();
  }
}

void SecurityRecordStorage::LoadSecurityRecords(std::set<std::shared_ptr<record::SecurityRecord>>* records) {
  for (auto device : storage_module_->GetBondedDevices()) {
    auto address_type = (device.GetDeviceType() == hci::DeviceType::BR_EDR) ? hci::AddressType::PUBLIC_DEVICE_ADDRESS
                                                                            : device.Le().GetAddressType();
    auto address_with_type = hci::AddressWithType(device.Classic().GetAddress(), *address_type);
    auto record = std::make_shared<record::SecurityRecord>(address_with_type);
    if (device.GetDeviceType() != hci::DeviceType::LE) {
      record->SetLinkKey(device.Classic().GetLinkKey()->bytes, *device.Classic().GetLinkKeyType());
    }
    if (device.GetDeviceType() != hci::DeviceType::BR_EDR) {
      record->identity_address_ =
          std::make_optional<hci::AddressWithType>(*device.Le().GetIdentityAddress(), *device.Le().GetAddressType());
      record->pseudo_address_ = std::make_optional<hci::AddressWithType>(
          *device.Le().GetLegacyPseudoAddress(), *device.Le().GetAddressType());
      auto byte_array = common::ByteArray<16>::FromString(*device.Le().GetLtk());
      record->ltk = std::make_optional<std::array<uint8_t, 16>>(byte_array->bytes);
      record->ediv = device.Le().GetEdiv();
      auto byte_array2 = common::ByteArray<8>::FromString(*device.Le().GetRand());
      record->rand = std::make_optional<std::array<uint8_t, 8>>(byte_array2->bytes);
      byte_array = common::ByteArray<16>::FromString(*device.Le().GetIrk());
      record->irk = std::make_optional<std::array<uint8_t, 16>>(byte_array->bytes);
      byte_array = common::ByteArray<16>::FromString(*device.Le().GetSignatureKey());
      record->signature_key = std::make_optional<std::array<uint8_t, 16>>(byte_array->bytes);
    }
    record->SetIsEncrypted(false);
    record->SetIsEncryptionRequired(device.GetIsEncryptionRequired() == 1 ? true : false);
    record->SetAuthenticated(device.GetIsAuthenticated() == 1 ? true : false);
    record->SetRequiresMitmProtection(device.GetRequiresMitmProtection() == 1 ? true : false);
    records->insert(record);
  }
}

void SecurityRecordStorage::RemoveDevice(hci::AddressWithType address) {
  storage::Device device = storage_module_->GetDeviceByClassicMacAddress(address.GetAddress());
  auto mutation = storage_module_->Modify();
  mutation.Add(device.RemoveFromConfig());
  mutation.Commit();
}

}  // namespace record
}  // namespace security
}  // namespace bluetooth
