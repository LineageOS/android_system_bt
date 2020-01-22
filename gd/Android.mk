LOCAL_PATH := $(call my-dir)

PRIVATE_BLUETOOTH_CERT_TEST_FILE_LIST := \
    $(call all-named-files-under,*.py,cert) \
    $(call all-named-files-under,*.sh,cert) \
    cert/cert_testcases \
    cert/cert_testcases_facade_only \
    cert/host_only_config.json \
    cert/host_only_config_facade_only.json \
    hal/cert/simple_hal_test.py \
    hci/cert/acl_manager_test.py \
    hci/cert/controller_test.py \
    hci/cert/direct_hci_test.py \
    hci/cert/le_advertising_manager_test.py \
    hci/cert/le_scanning_manager_test.py \
    l2cap/classic/cert/simple_l2cap_test.py \
    l2cap/classic/cert/pts_l2cap_test.py \
    neighbor/cert/neighbor_test.py


PRIVATE_BLUETOOTH_CERT_TEST_FILE_LIST := $(addprefix $(LOCAL_PATH)/,$(PRIVATE_BLUETOOTH_CERT_TEST_FILE_LIST))

PRIVATE_BLUETOOTH_CERT_ZIP_PATH := \
    $(call intermediates-dir-for,PACKAGING,bluetooth_cert_test_package,HOST)/bluetooth_cert_test.zip

$(PRIVATE_BLUETOOTH_CERT_ZIP_PATH) : $(SOONG_ZIP) $(PRIVATE_BLUETOOTH_CERT_TEST_FILE_LIST)
	$(hide) $(SOONG_ZIP) -d -o $@ -C system/bt/gd $(addprefix -f ,$(PRIVATE_BLUETOOTH_CERT_TEST_FILE_LIST))

$(call dist-for-goals,libbluetooth_gd,$(PRIVATE_BLUETOOTH_CERT_ZIP_PATH):bluetooth_cert_test/bluetooth_cert_test.zip)
