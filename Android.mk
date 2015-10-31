LOCAL_PATH := $(call my-dir)

# Setup bdroid local make variables for handling configuration
ifneq ($(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR),)
  bdroid_C_INCLUDES := $(BOARD_BLUETOOTH_BDROID_BUILDCFG_INCLUDE_DIR)
  bdroid_CFLAGS += -DHAS_BDROID_BUILDCFG
else
  bdroid_C_INCLUDES :=
  bdroid_CFLAGS += -DHAS_NO_BDROID_BUILDCFG
endif

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
ifneq ($(BOARD_HAS_QCA_BT_ROME),true)
bdroid_CFLAGS += -DQLOGKIT_USERDEBUG
endif
endif

ifneq ($(BOARD_BLUETOOTH_BDROID_HCILP_INCLUDED),)
  bdroid_CFLAGS += -DHCILP_INCLUDED=$(BOARD_BLUETOOTH_BDROID_HCILP_INCLUDED)
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
bdroid_CFLAGS += -DBLUEDROID_DEBUG
bdroid_CFLAGS += -DUSE_AUDIO_TRACK
endif

ifeq ($(BOARD_USES_WIPOWER), true)
bdroid_CFLAGS  += -DWIPOWER_SUPPORTED
endif

bdroid_CFLAGS += \
  -Wall \
  -Wno-unused-parameter \
  -Wunused-but-set-variable \
  -UNDEBUG \
  -DLOG_NDEBUG=1

include $(call all-subdir-makefiles)

# Cleanup our locals
bdroid_C_INCLUDES :=
bdroid_CFLAGS :=
