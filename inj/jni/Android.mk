LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=  elf_utils.c poison.c ptrace_utils.c tools.c
LOCAL_MODULE := zygote
LOCAL_LDLIBS := -llog
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -DANDROID -DTHUMB
#LOCAL_C_INCLUDES := 
include $(BUILD_EXECUTABLE)






