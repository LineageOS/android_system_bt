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

#include <base/files/file_util.h>
#include <base/logging.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>
#include <fstream>

#include "btif/include/btif_keystore.h"

using namespace bluetooth;

constexpr char kFilename[] = "/data/misc/bluedroid/testfile.txt";

class BtifKeystoreTest : public ::testing::Test {
 protected:
  std::unique_ptr<BtifKeystore> btif_keystore_;
  base::FilePath file_path_;
  BtifKeystoreTest() : file_path_(kFilename) {}
  void SetUp() override {
    android::ProcessState::self()->startThreadPool();
    btif_keystore_ =
        std::make_unique<BtifKeystore>(static_cast<keystore::KeystoreClient*>(
            new keystore::KeystoreClientImpl));
    base::DeleteFile(file_path_, true);
  };
  void TearDown() override { btif_keystore_ = nullptr; };
};

// Encrypt
TEST_F(BtifKeystoreTest, test_encrypt_decrypt) {
  std::string hash = "test";

  EXPECT_TRUE(btif_keystore_->Encrypt(hash, kFilename, 0));
  std::string decrypted_hash = btif_keystore_->Decrypt(kFilename);

  EXPECT_TRUE(base::PathExists(file_path_));
  EXPECT_EQ(hash, decrypted_hash);
}

TEST_F(BtifKeystoreTest, test_encrypt_empty_hash) {
  std::string hash = "";

  EXPECT_FALSE(btif_keystore_->Encrypt(hash, kFilename, 0));

  EXPECT_FALSE(base::PathExists(file_path_));
}

TEST_F(BtifKeystoreTest, test_encrypt_empty_filename) {
  std::string hash = "test";

  EXPECT_FALSE(btif_keystore_->Encrypt(hash, "", 0));

  EXPECT_FALSE(base::PathExists(file_path_));
}

// Decrypt
TEST_F(BtifKeystoreTest, test_decrypt_empty_hash) {
  // Only way to get the hash to decrypt is to read it from the file
  // So make empty file manually
  std::ofstream outfile(kFilename);
  outfile.close();

  std::string decrypted_hash = btif_keystore_->Decrypt(kFilename);

  EXPECT_TRUE(decrypted_hash.empty());
}

TEST_F(BtifKeystoreTest, test_decrypt_file_not_exist) {
  // Ensure file doesn't exist, then decrypt
  EXPECT_FALSE(base::PathExists(file_path_));

  std::string decrypted_hash = btif_keystore_->Decrypt(kFilename);

  EXPECT_TRUE(decrypted_hash.empty());
}

TEST_F(BtifKeystoreTest, test_decrypt_empty_filename) {
  std::string decrypted_hash = btif_keystore_->Decrypt("");

  EXPECT_TRUE(decrypted_hash.empty());
}
