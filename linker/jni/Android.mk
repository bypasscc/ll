LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := linker
LOCAL_SRC_FILES := linker.cpp main.cpp

#LOCAL_CFLAGS := -std=gnu99

include $(BUILD_EXECUTABLE)
