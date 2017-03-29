LOCAL_PATH := $(call my-dir)

# test-vendor shared library for target
# ========================================================
include $(CLEAR_VARS)

BT_DIR := $(TOP_DIR)system/bt

LOCAL_SRC_FILES := \
    src/async_manager.cc \
    src/bt_address.cc \
    src/bt_vendor.cc \
    src/command_packet.cc \
    src/dual_mode_controller.cc \
    src/event_packet.cc \
    src/hci_transport.cc \
    src/packet.cc \
    src/packet_stream.cc \
    src/test_channel_transport.cc \
    src/vendor_manager.cc

# We pull in gtest because base/files/file_util.h, which is used to read the
# controller properties file, needs gtest/gtest_prod.h.
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    $(BT_DIR) \
    $(BT_DIR)/include \
    $(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR) \
    $(BT_DIR)/utils/include \
    $(BT_DIR)/hci/include \
    $(BT_DIR)/stack/include \
    $(BT_DIR)/third_party/gtest/include

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libchrome

LOCAL_CPP_EXTENSION := .cc
# On some devices this is the actual vendor library. On other devices build
# as a test library.
ifneq (,$(BOARD_BLUETOOTH_USE_TEST_AS_VENDOR))
LOCAL_MODULE := libbt-vendor
LOCAL_MODULE_OWNER := google
LOCAL_PROPRIETARY_MODULE := true
LOCAL_CFLAGS += -DBLUETOOTH_USE_TEST_AS_VENDOR
ifeq ($(TARGET_TRANSLATE_2ND_ARCH),true)
# If its vendor library and secondary arch is translated then only one library
# is provided
ifneq (1,$(words $(LOCAL_MODULE_TARGET_ARCH)))
LOCAL_MULTILIB := first
endif
endif
else
LOCAL_MODULE := test-vendor
endif
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES

LOCAL_CFLAGS += $(test-vendor_CFLAGS)

include $(BUILD_SHARED_LIBRARY)
