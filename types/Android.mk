LOCAL_PATH := $(call my-dir)

# support types for ASB 2018-09-01
# ========================================================
include $(CLEAR_VARS)

BT_DIR := $(TOP_DIR)system/bt

LOCAL_SRC_FILES := \
    raw_address.cc

# We pull in gtest because base/files/file_util.h, which is used to read the
# controller properties file, needs gtest/gtest_prod.h.
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \
    $(BT_DIR) \
    $(BT_DIR)/hci/include \
    $(BT_DIR)/stack/include \

LOCAL_CPP_EXTENSION := .cc
LOCAL_MODULE := libbttypes
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

LOCAL_CFLAGS += $(bluetooth_CFLAGS)
LOCAL_CONLYFLAGS += $(bluetooth_CONLYFLAGS)
LOCAL_CPPFLAGS += $(bluetooth_CPPFLAGS)

include $(BUILD_STATIC_LIBRARY)
