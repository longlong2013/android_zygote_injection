/*
 * ptrace_utils.c
 *
 *  Created on: 2014-7
 *      Author: long
 * modify from author: boyliang 
 */

#ifndef LOG_H_
#define LOG_H_

#include <android/log.h>

#define LOG_TAG "zygote-injection"
#define DEBUG 1

#ifdef DEBUG
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGI(...) while(0)
#define LOGE(...) while(0)
#endif

#endif /* LOG_H_ */
