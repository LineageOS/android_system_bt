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

#include "mock_hcic_layer.h"

static hcic::MockHcicInterface* hcic_interface = nullptr;

void hcic::SetMockHcicInterface(MockHcicInterface* interface) {
  hcic_interface = interface;
}

void btsnd_hcic_set_cig_params(
    uint8_t cig_id, uint32_t sdu_itv_mtos, uint32_t sdu_itv_stom, uint8_t sca,
    uint8_t packing, uint8_t framing, uint16_t max_trans_lat_stom,
    uint16_t max_trans_lat_mtos, uint8_t cis_cnt, const EXT_CIS_CFG* cis_cfg,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  struct bluetooth::hci::iso_manager::cig_create_params cig_params = {
      .sdu_itv_mtos = sdu_itv_mtos,
      .sdu_itv_stom = sdu_itv_stom,
      .sca = sca,
      .packing = packing,
      .framing = framing,
      .max_trans_lat_stom = max_trans_lat_stom,
      .max_trans_lat_mtos = max_trans_lat_mtos,
      .cis_cfgs = std::vector(cis_cfg, cis_cfg + cis_cnt),
  };
  hcic_interface->SetCigParams(cig_id, std::move(cig_params), std::move(cb));
}

void btsnd_hcic_remove_cig(uint8_t cig_id,
                           base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  hcic_interface->RemoveCig(cig_id, std::move(cb));
}

void btsnd_hcic_create_cis(uint8_t num_cis, const EXT_CIS_CREATE_CFG* cis_cfg,
                           base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  hcic_interface->CreateCis(num_cis, cis_cfg, std::move(cb));
}

void btsnd_hcic_disconnect(uint16_t handle, uint8_t reason) {
  hcic_interface->Disconnect(handle, reason);
}

void btsnd_hcic_setup_iso_data_path(
    uint16_t iso_handle, uint8_t data_path_dir, uint8_t data_path_id,
    uint8_t codec_id_format, uint16_t codec_id_company,
    uint16_t codec_id_vendor, uint32_t controller_delay,
    std::vector<uint8_t> codec_conf,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  hcic_interface->SetupIsoDataPath(iso_handle, data_path_dir, data_path_id,
                                   codec_id_format, codec_id_company,
                                   codec_id_vendor, controller_delay,
                                   std::move(codec_conf), std::move(cb));
}

void btsnd_hcic_remove_iso_data_path(
    uint16_t iso_handle, uint8_t data_path_dir,
    base::OnceCallback<void(uint8_t*, uint16_t)> cb) {
  hcic_interface->RemoveIsoDataPath(iso_handle, data_path_dir, std::move(cb));
}
