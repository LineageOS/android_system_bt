#!/bin/bash

destdir="$1"

header_dirs=(
    base
    base/allocator
    base/containers
    base/debug
    base/files
    base/hash
    base/i18n
    base/json
    base/memory
    base/message_loop
    base/metrics
    base/numerics
    base/posix
    base/process
    base/strings
    base/synchronization
    base/system
    base/task
    base/task/common
    base/task/sequence_manager
    base/task/thread_pool
    base/test
    base/third_party/icu
    base/third_party/nspr
    base/third_party/valgrind
    base/threading
    base/time
    base/timer
    base/trace_event
    base/trace_event/common
    build
    components/policy
    components/policy/core/common
    testing/gmock/include/gmock
    testing/gtest/include/gtest
    dbus
  )

# Install header files.
for d in "${header_dirs[@]}" ; do
  mkdir -p "${destdir}/usr/include/libchrome/${d}"
  cp libchrome/"${d}"/*.h "${destdir}/usr/include/libchrome/${d}"
done
