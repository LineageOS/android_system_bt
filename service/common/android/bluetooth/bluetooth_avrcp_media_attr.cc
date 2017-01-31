//
//  Copyright 2017 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#include "android/bluetooth/bluetooth_avrcp_media_attr.h"

#include <utils/String16.h>
#include <utils/String8.h>

using android::OK;
using android::String16;
using android::String8;

namespace android {
namespace bluetooth {

status_t BluetoothAvrcpMediaAttr::writeToParcel(Parcel* parcel) const {
  status_t status = parcel->writeString16(title_);
  if (status != OK) return status;

  status = parcel->writeString16(artist_);
  if (status != OK) return status;

  status = parcel->writeString16(album_);
  if (status != OK) return status;

  status = parcel->writeString16(genre_);
  if (status != OK) return status;

  status = parcel->writeInt32(track_num_);
  if (status != OK) return status;

  status = parcel->writeInt32(num_tracks_);
  if (status != OK) return status;

  status = parcel->writeInt32(play_time_);
  if (status != OK) return status;

  return status;
}

status_t BluetoothAvrcpMediaAttr::readFromParcel(const Parcel* parcel) {
  status_t status = parcel->readString16(&title_);
  if (status != OK) return status;

  status = parcel->readString16(&artist_);
  if (status != OK) return status;

  status = parcel->readString16(&album_);
  if (status != OK) return status;

  status = parcel->readString16(&genre_);
  if (status != OK) return status;

  int32_t tmp;
  status = parcel->readInt32(&tmp);
  if (status != OK) return status;
  track_num_ = tmp;

  status = parcel->readInt32(&tmp);
  if (status != OK) return status;
  num_tracks_ = tmp;

  status = parcel->readInt32(&tmp);
  if (status != OK) return status;
  play_time_ = tmp;

  return status;
}

}  // namespace bluetooth
}  // namespace android
