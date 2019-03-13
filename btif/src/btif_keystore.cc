/******************************************************************************
 *
 *  Copyright 2019 Google, Inc.
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
 ******************************************************************************/

#define LOG_TAG "bt_btif_keystore"

#include "btif_keystore.h"
#include "osi/include/properties.h"

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/utf_string_conversions.h>
#include <sys/stat.h>

using namespace keystore;

static std::unique_ptr<keystore::KeystoreClient> CreateKeystoreInstance(void);
static void WriteFile(const std::string& filename, const std::string& content);
static std::string ReadFile(const std::string& filename);
static int GenerateKey(const std::string& name, int32_t flags, bool auth_bound);
static bool DoesKeyExist(const std::string& name);

const std::string FILE_SUFFIX = ".encrypted-checksum";
const std::string CIPHER_ALGORITHM = "AES/GCM/NoPadding";
const std::string DIGEST_ALGORITHM = "SHA-256";
const std::string KEY_STORE = "AndroidKeystore";

std::unique_ptr<KeystoreClient> keystoreClient;

BtifKeystore::BtifKeystore() { keystoreClient = CreateKeystoreInstance(); }

BtifKeystore::~BtifKeystore() {
  // Using a smart pointer, does it delete itself?
  // delete keystoreClient;
}

int BtifKeystore::Encrypt(const std::string& hash,
                          const std::string& output_filename, int32_t flags) {
  std::string output;
  if (!DoesKeyExist(KEY_STORE)) {
    GenerateKey(KEY_STORE, 0, false);
  }
  char is_unittest[PROPERTY_VALUE_MAX] = {0};
  osi_property_get("debug.bluetooth.unittest", is_unittest, "false");
  if (strcmp(is_unittest, "false") == 0) {
    if (!keystoreClient->encryptWithAuthentication(KEY_STORE, hash, flags,
                                                   &output)) {
      LOG(ERROR) << "EncryptWithAuthentication failed.\n";
      return 1;
    }
  }
  WriteFile(output_filename, output);
  return 0;
}

std::string BtifKeystore::Decrypt(const std::string& input_filename) {
  std::string input = ReadFile(input_filename);
  std::string output;

  char is_unittest[PROPERTY_VALUE_MAX] = {0};
  osi_property_get("debug.bluetooth.unittest", is_unittest, "false");
  if (strcmp(is_unittest, "false") == 0) {
    if (!keystoreClient->decryptWithAuthentication(KEY_STORE, input, &output)) {
      LOG(ERROR) << "DecryptWithAuthentication failed.\n";
    }
  }
  return output;
}

static std::string ReadFile(const std::string& filename) {
  std::string content;
  struct stat buffer;
  if (stat(filename.c_str(), &buffer) == 0) {
    base::FilePath path(filename);
    if (!base::ReadFileToString(path, &content)) {
      LOG(ERROR) << "ReadFile failed.\n" << filename.c_str();
    }
  }
  return content;
}

static void WriteFile(const std::string& filename, const std::string& content) {
  base::FilePath path(filename);
  int size = content.size();
  if (base::WriteFile(path, content.data(), size) != size) {
    LOG(ERROR) << "WriteFile failed.\n" << filename.c_str();
  }
}

// Note: auth_bound keys created with this tool will not be usable.
static int GenerateKey(const std::string& name, int32_t flags,
                       bool auth_bound) {
  AuthorizationSetBuilder params;
  params.RsaSigningKey(2048, 65537)
      .Digest(Digest::SHA_2_224)
      .Digest(Digest::SHA_2_256)
      .Digest(Digest::SHA_2_384)
      .Digest(Digest::SHA_2_512)
      .Padding(PaddingMode::RSA_PKCS1_1_5_SIGN)
      .Padding(PaddingMode::RSA_PSS);
  if (auth_bound) {
    // Gatekeeper normally generates the secure user id.
    // Using zero allows the key to be created, but it will not be usuable.
    params.Authorization(TAG_USER_SECURE_ID, 0);
  } else {
    params.Authorization(TAG_NO_AUTH_REQUIRED);
  }
  AuthorizationSet hardware_enforced_characteristics;
  AuthorizationSet software_enforced_characteristics;

  char is_unittest[PROPERTY_VALUE_MAX] = {0};
  osi_property_get("debug.bluetooth.unittest", is_unittest, "false");
  if (strcmp(is_unittest, "false") != 0) {
      return -1;
  }
  auto result = keystoreClient->generateKey(name, params, flags,
                                            &hardware_enforced_characteristics,
                                            &software_enforced_characteristics);
  return result.getErrorCode();
}

static bool DoesKeyExist(const std::string& name) {
  return keystoreClient->doesKeyExist(name) ? true : false;
}

static std::unique_ptr<KeystoreClient> CreateKeystoreInstance(void) {
  return std::unique_ptr<KeystoreClient>(
      static_cast<KeystoreClient*>(new KeystoreClientImpl));
}
