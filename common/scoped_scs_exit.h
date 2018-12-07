/*
 * Copyright 2018 The Android Open Source Project
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

#pragma once

// Prevent x18 (shadow call stack address) from being clobbered by functions
// called by a function that declares a variable of this type by temporarily
// storing the value on the stack. This is used only when calling out to certain
// vendor libraries.
struct ScopedSCSExit {
#ifdef __aarch64__
    void* scs;

    __attribute__((always_inline, no_sanitize("shadow-call-stack"))) ScopedSCSExit() {
        __asm__ __volatile__("str x18, [%0]" ::"r"(&scs));
    }

    __attribute__((always_inline, no_sanitize("shadow-call-stack"))) ~ScopedSCSExit() {
        __asm__ __volatile__("ldr x18, [%0]; str xzr, [%0]" ::"r"(&scs));
    }
#else
    // Silence unused variable warnings in non-SCS builds.
    __attribute__((no_sanitize("shadow-call-stack"))) ScopedSCSExit() {}
    __attribute__((no_sanitize("shadow-call-stack"))) ~ScopedSCSExit() {}
#endif
};
