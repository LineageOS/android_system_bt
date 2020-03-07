LOCAL_PATH := $(call my-dir)

bluetooth_cert_test_file_list := \
    $(call all-named-files-under,*.py,.) \
    $(call all-named-files-under,*.proto,cert facade hal hci/cert hci/facade l2cap/classic \
	    l2cap/classic/cert neighbor/facade security) \
    cert/all_cert_testcases

bluetooth_cert_test_file_list := $(addprefix $(LOCAL_PATH)/,$(bluetooth_cert_test_file_list))

bluetooth_cert_test_file_list += \
    $(HOST_OUT_EXECUTABLES)/bluetooth_stack_with_facade \
    $(HOST_OUT_SHARED_LIBRARIES)/bluetooth_packets_python3.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libbase.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libbluetooth_gd.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libc++.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libchrome.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libevent-host.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libgrpc++_unsecure.so \
    $(HOST_OUT_SHARED_LIBRARIES)/liblog.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libz-host.so \
    $(HOST_OUT_SHARED_LIBRARIES)/libprotobuf-cpp-full.so \
    $(TARGET_OUT_EXECUTABLES)/bluetooth_stack_with_facade \
    $(TARGET_OUT_SHARED_LIBRARIES)/libbluetooth_gd.so \
    $(TARGET_OUT_SHARED_LIBRARIES)/libgrpc++_unsecure.so \
    $(HOST_OUT_NATIVE_TESTS)/root-canal/root-canal

bluetooth_cert_env_provider_path := \
    $(call intermediates-dir-for,PACKAGING,bluetooth_cert_test_package,HOST)/system/bt/gd/cert/environment_provider.py

$(bluetooth_cert_env_provider_path):
	@mkdir -p $(dir $@)
	$(hide) echo "PRODUCT_DEVICE = \"$(PRODUCT_DEVICE)\"" > $@

bluetooth_cert_zip_path := \
    $(call intermediates-dir-for,PACKAGING,bluetooth_cert_test_package,HOST)/bluetooth_cert_test.zip

$(bluetooth_cert_zip_path): PRIVATE_BLUETOOTH_CERT_TEST_FILE_LIST := $(bluetooth_cert_test_file_list)

$(bluetooth_cert_zip_path): PRIVATE_BLUETOOTH_CERT_ENV_PROVIDER_PATH := $(bluetooth_cert_env_provider_path)

$(bluetooth_cert_zip_path) : $(SOONG_ZIP) $(bluetooth_cert_env_provider_path) $(bluetooth_cert_test_file_list)
	$(hide) $(SOONG_ZIP) -d -o $@ $(addprefix -f ,$(PRIVATE_BLUETOOTH_CERT_TEST_FILE_LIST)) \
		-C $(call intermediates-dir-for,PACKAGING,bluetooth_cert_test_package,HOST) -f $(PRIVATE_BLUETOOTH_CERT_ENV_PROVIDER_PATH)

$(call dist-for-goals,bluetooth_stack_with_facade,$(bluetooth_cert_zip_path):bluetooth_cert_test.zip)
