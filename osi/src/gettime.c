/*
 * Copyright (C) 2015, The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <linux/android_alarm.h>
#include <linux/ioctl.h>
#include <linux/rtc.h>
#include <utils/Atomic.h>

#include "gettime.h"

#define USEC_PER_SEC            1000000L
#define NSEC_PER_USEC           1000

int gettime_now(struct timespec *now)
{
    static int s_fd = -1;
    int result;

    if (s_fd == -1) {
        int fd = open("/dev/alarm", O_RDONLY);
        if (android_atomic_cmpxchg(-1, fd, &s_fd)) {
            close(fd);
        }
    }

    result = ioctl(s_fd,
            ANDROID_ALARM_GET_TIME(ANDROID_ALARM_ELAPSED_REALTIME), now);
    if (result != 0) {
        result = clock_gettime(CLOCK_BOOTTIME, now);
    }

    return result;
}

int gettime_now_us(uint64_t *now_us)
{
    struct timespec now;
    int result;

    result = gettime_now(&now);
    if (!result) {
        *now_us = ((uint64_t)now.tv_sec * USEC_PER_SEC) +
                  ((uint64_t)now.tv_nsec / NSEC_PER_USEC);
    }

    return result;
}

