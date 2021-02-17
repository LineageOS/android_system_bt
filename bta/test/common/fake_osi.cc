/*
 * Copyright 2021 The Android Open Source Project
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

/*
 * Generated mock file from original source file
 */

#include <list>
#include <map>
#include <string>

extern std::map<std::string, int> mock_function_count_map;

#include "osi/src/compat.cc"  // For strlcpy

#include "osi/include/alarm.h"
#include "osi/include/allocator.h"
#include "osi/include/array.h"
#include "osi/include/buffer.h"
#include "osi/include/config.h"
#include "osi/include/fixed_queue.h"
#include "osi/include/future.h"
#include "osi/include/hash_map_utils.h"
#include "osi/include/list.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/reactor.h"
#include "osi/include/ringbuffer.h"
#include "osi/include/semaphore.h"
#include "osi/include/socket.h"
#include "osi/include/thread.h"
#include "osi/include/wakelock.h"
#include "test/common/fake_osi.h"

#ifndef UNUSED_ATTR
#define UNUSED_ATTR
#endif

std::list<entry_t>::iterator section_t::Find(const std::string& key) {
  mock_function_count_map[__func__]++;
  return std::find_if(
      entries.begin(), entries.end(),
      [&key](const entry_t& entry) { return entry.key == key; });
}
std::list<section_t>::iterator config_t::Find(const std::string& section) {
  mock_function_count_map[__func__]++;
  return std::find_if(
      sections.begin(), sections.end(),
      [&section](const section_t& sec) { return sec.name == section; });
}

bool checksum_save(const std::string& checksum, const std::string& filename) {
  mock_function_count_map[__func__]++;
  return false;
}
bool config_get_bool(const config_t& config, const std::string& section,
                     const std::string& key, bool def_value) {
  mock_function_count_map[__func__]++;
  return false;
}
bool config_has_key(const config_t& config, const std::string& section,
                    const std::string& key) {
  mock_function_count_map[__func__]++;
  return false;
}
bool config_has_section(const config_t& config, const std::string& section) {
  mock_function_count_map[__func__]++;
  return false;
}
bool config_remove_key(config_t* config, const std::string& section,
                       const std::string& key) {
  mock_function_count_map[__func__]++;
  return false;
}
bool config_remove_section(config_t* config, const std::string& section) {
  mock_function_count_map[__func__]++;
  return false;
}
bool config_save(const config_t& config, const std::string& filename) {
  mock_function_count_map[__func__]++;
  return false;
}
bool config_t::Has(const std::string& key) {
  mock_function_count_map[__func__]++;
  return false;
}
bool section_t::Has(const std::string& key) {
  mock_function_count_map[__func__]++;
  return false;
}
const std::string* config_get_string(const config_t& config,
                                     const std::string& section,
                                     const std::string& key,
                                     const std::string* def_value) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
int config_get_int(const config_t& config, const std::string& section,
                   const std::string& key, int def_value) {
  mock_function_count_map[__func__]++;
  return 0;
}
std::string checksum_read(const char* filename) {
  mock_function_count_map[__func__]++;
  return 0;
}
std::unique_ptr<config_t> config_new(const char* filename) {
  mock_function_count_map[__func__]++;
  return 0;
}
std::unique_ptr<config_t> config_new_clone(const config_t& src) {
  mock_function_count_map[__func__]++;
  return 0;
}
std::unique_ptr<config_t> config_new_empty(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
uint64_t config_get_uint64(const config_t& config, const std::string& section,
                           const std::string& key, uint64_t def_value) {
  mock_function_count_map[__func__]++;
  return 0;
}
void config_set_bool(config_t* config, const std::string& section,
                     const std::string& key, bool value) {
  mock_function_count_map[__func__]++;
}
void config_set_int(config_t* config, const std::string& section,
                    const std::string& key, int value) {
  mock_function_count_map[__func__]++;
}
void config_set_string(config_t* config, const std::string& section,
                       const std::string& key, const std::string& value) {
  mock_function_count_map[__func__]++;
}
void config_set_uint64(config_t* config, const std::string& section,
                       const std::string& key, uint64_t value) {
  mock_function_count_map[__func__]++;
}
void section_t::Set(std::string key, std::string value) {
  mock_function_count_map[__func__]++;
}

bool array_append_ptr(array_t* array, void* data) {
  mock_function_count_map[__func__]++;
  return false;
}
bool array_append_value(array_t* array, uint32_t value) {
  mock_function_count_map[__func__]++;
  return false;
}
size_t array_length(const array_t* array) {
  mock_function_count_map[__func__]++;
  return 0;
}
void array_free(array_t* array) { mock_function_count_map[__func__]++; }
void* array_at(const array_t* array, size_t index) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* array_ptr(const array_t* array) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

size_t allocation_tracker_expect_no_allocations(void) {
  mock_function_count_map[__func__]++;
  return 0;
}
size_t allocation_tracker_resize_for_canary(size_t size) {
  mock_function_count_map[__func__]++;
  return 0;
}
void allocation_tracker_reset(void) { mock_function_count_map[__func__]++; }
void allocation_tracker_uninit(void) { mock_function_count_map[__func__]++; }
void osi_allocator_debug_dump(int fd) { mock_function_count_map[__func__]++; }
void* allocation_tracker_notify_alloc(uint8_t allocator_id, void* ptr,
                                      size_t requested_size) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* allocation_tracker_notify_free(UNUSED_ATTR uint8_t allocator_id,
                                     void* ptr) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

bool reactor_change_registration(reactor_object_t* object,
                                 void (*read_ready)(void* context),
                                 void (*write_ready)(void* context)) {
  mock_function_count_map[__func__]++;
  return false;
}
reactor_object_t* reactor_register(reactor_t* reactor, int fd, void* context,
                                   void (*read_ready)(void* context),
                                   void (*write_ready)(void* context)) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
reactor_status_t reactor_run_once(reactor_t* reactor) {
  mock_function_count_map[__func__]++;
  return REACTOR_STATUS_DONE;
}
reactor_status_t reactor_start(reactor_t* reactor) {
  mock_function_count_map[__func__]++;
  return REACTOR_STATUS_DONE;
}
reactor_t* reactor_new(void) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void reactor_free(reactor_t* reactor) { mock_function_count_map[__func__]++; }
void reactor_stop(reactor_t* reactor) { mock_function_count_map[__func__]++; }
void reactor_unregister(reactor_object_t* obj) {
  mock_function_count_map[__func__]++;
}

future_t* future_new(void) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
future_t* future_new_immediate(void* value) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void future_ready(future_t* future, void* value) {
  mock_function_count_map[__func__]++;
}
void mutex_global_lock(void) { mock_function_count_map[__func__]++; }
void mutex_global_unlock(void) { mock_function_count_map[__func__]++; }
void* future_await(future_t* future) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

bool thread_is_self(const thread_t* thread) {
  mock_function_count_map[__func__]++;
  return false;
}
bool thread_post(thread_t* thread, thread_fn func, void* context) {
  mock_function_count_map[__func__]++;
  return false;
}
bool thread_set_priority(thread_t* thread, int priority) {
  mock_function_count_map[__func__]++;
  return false;
}
bool thread_set_rt_priority(thread_t* thread, int priority) {
  mock_function_count_map[__func__]++;
  return false;
}
const char* thread_name(const thread_t* thread) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
reactor_t* thread_get_reactor(const thread_t* thread) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
thread_t* thread_new(const char* name) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
thread_t* thread_new_sized(const char* name, size_t work_queue_capacity) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void thread_free(thread_t* thread) { mock_function_count_map[__func__]++; }
void thread_join(thread_t* thread) { mock_function_count_map[__func__]++; }
void thread_stop(thread_t* thread) { mock_function_count_map[__func__]++; }

char* osi_strdup(const char* str) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
char* osi_strndup(const char* str, size_t len) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void osi_free(void* ptr) { mock_function_count_map[__func__]++; }
void osi_free_and_reset(void** p_ptr) { mock_function_count_map[__func__]++; }
void* osi_calloc(size_t size) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* osi_malloc(size_t size) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

bool fixed_queue_is_empty(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return false;
}
bool fixed_queue_try_enqueue(fixed_queue_t* queue, void* data) {
  mock_function_count_map[__func__]++;
  return false;
}
fixed_queue_t* fixed_queue_new(size_t capacity) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
int fixed_queue_get_dequeue_fd(const fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return 0;
}
int fixed_queue_get_enqueue_fd(const fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return 0;
}
list_t* fixed_queue_get_list(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
size_t fixed_queue_capacity(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return 0;
}
size_t fixed_queue_length(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return 0;
}
void fixed_queue_enqueue(fixed_queue_t* queue, void* data) {
  mock_function_count_map[__func__]++;
}
void fixed_queue_flush(fixed_queue_t* queue, fixed_queue_free_cb free_cb) {
  mock_function_count_map[__func__]++;
}
void fixed_queue_free(fixed_queue_t* queue, fixed_queue_free_cb free_cb) {
  mock_function_count_map[__func__]++;
}
void fixed_queue_register_dequeue(fixed_queue_t* queue, reactor_t* reactor,
                                  fixed_queue_cb ready_cb, void* context) {
  mock_function_count_map[__func__]++;
}
void fixed_queue_unregister_dequeue(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
}
void* fixed_queue_dequeue(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* fixed_queue_try_dequeue(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* fixed_queue_try_peek_first(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* fixed_queue_try_peek_last(fixed_queue_t* queue) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* fixed_queue_try_remove_from_queue(fixed_queue_t* queue, void* data) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

alarm_t* alarm_new(const char* name) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
alarm_t* alarm_new_periodic(const char* name) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
bool alarm_is_scheduled(const alarm_t* alarm) {
  mock_function_count_map[__func__]++;
  return false;
}
uint64_t alarm_get_remaining_ms(const alarm_t* alarm) {
  mock_function_count_map[__func__]++;
  return 0;
}
void alarm_cancel(alarm_t* alarm) { mock_function_count_map[__func__]++; }
void alarm_cleanup(void) { mock_function_count_map[__func__]++; }
void alarm_debug_dump(int fd) { mock_function_count_map[__func__]++; }
void alarm_free(alarm_t* alarm) { mock_function_count_map[__func__]++; }
void alarm_set(alarm_t* alarm, uint64_t interval_ms, alarm_callback_t cb,
               void* data) {
  mock_function_count_map[__func__]++;
}

struct fake_osi_alarm_set_on_mloop fake_osi_alarm_set_on_mloop_;
void alarm_set_on_mloop(alarm_t* alarm, uint64_t interval_ms,
                        alarm_callback_t cb, void* data) {
  mock_function_count_map[__func__]++;
  fake_osi_alarm_set_on_mloop_.interval_ms = interval_ms;
  fake_osi_alarm_set_on_mloop_.cb = cb;
  fake_osi_alarm_set_on_mloop_.data = data;
}

int osi_rand(void) {
  mock_function_count_map[__func__]++;
  return 0;
}

buffer_t* buffer_new_ref(const buffer_t* buf) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
buffer_t* buffer_new_slice(const buffer_t* buf, size_t slice_size) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
size_t buffer_length(const buffer_t* buf) {
  mock_function_count_map[__func__]++;
  return 0;
}
void buffer_free(buffer_t* buffer) { mock_function_count_map[__func__]++; }
void* buffer_ptr(const buffer_t* buf) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

bool socket_listen(const socket_t* socket, port_t port) {
  mock_function_count_map[__func__]++;
  return false;
}
socket_t* socket_accept(const socket_t* socket) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
socket_t* socket_new(void) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
socket_t* socket_new_from_fd(int fd) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
ssize_t socket_bytes_available(const socket_t* socket) {
  mock_function_count_map[__func__]++;
  return 0;
}
ssize_t socket_read(const socket_t* socket, void* buf, size_t count) {
  mock_function_count_map[__func__]++;
  return 0;
}
ssize_t socket_write(const socket_t* socket, const void* buf, size_t count) {
  mock_function_count_map[__func__]++;
  return 0;
}
ssize_t socket_write_and_transfer_fd(const socket_t* socket, const void* buf,
                                     size_t count, int fd) {
  mock_function_count_map[__func__]++;
  return 0;
}
void socket_free(socket_t* socket) { mock_function_count_map[__func__]++; }
void socket_register(socket_t* socket, reactor_t* reactor, void* context,
                     socket_cb read_cb, socket_cb write_cb) {
  mock_function_count_map[__func__]++;
}
void socket_unregister(socket_t* socket) {
  mock_function_count_map[__func__]++;
}

bool list_append(list_t* list, void* data) {
  mock_function_count_map[__func__]++;
  return false;
}
bool list_contains(const list_t* list, const void* data) {
  mock_function_count_map[__func__]++;
  return false;
}
bool list_insert_after(list_t* list, list_node_t* prev_node, void* data) {
  mock_function_count_map[__func__]++;
  return false;
}
bool list_is_empty(const list_t* list) {
  mock_function_count_map[__func__]++;
  return false;
}
bool list_prepend(list_t* list, void* data) {
  mock_function_count_map[__func__]++;
  return false;
}
bool list_remove(list_t* list, void* data) {
  mock_function_count_map[__func__]++;
  return false;
}
list_node_t* list_back_node(const list_t* list) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
list_node_t* list_begin(const list_t* list) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
list_node_t* list_end(UNUSED_ATTR const list_t* list) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
list_node_t* list_foreach(const list_t* list, list_iter_cb callback,
                          void* context) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
list_node_t* list_next(const list_node_t* node) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
list_t* list_new(list_free_cb callback) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
list_t* list_new_internal(list_free_cb callback,
                          const allocator_t* zeroed_allocator) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
size_t list_length(const list_t* list) {
  mock_function_count_map[__func__]++;
  return 0;
}
void list_clear(list_t* list) { mock_function_count_map[__func__]++; }
void list_free(list_t* list) { mock_function_count_map[__func__]++; }
void* list_back(const list_t* list) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* list_front(const list_t* list) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void* list_node(const list_node_t* node) {
  mock_function_count_map[__func__]++;
  return nullptr;
}

int osi_socket_local_client(const char* name, int namespaceId, int type) {
  mock_function_count_map[__func__]++;
  return 0;
}
int osi_socket_local_client_connect(int fd, const char* name, int namespaceId,
                                    int type UNUSED_ATTR) {
  mock_function_count_map[__func__]++;
  return 0;
}
int osi_socket_local_server_bind(int s, const char* name, int namespaceId) {
  mock_function_count_map[__func__]++;
  return 0;
}
int osi_socket_make_sockaddr_un(const char* name, int namespaceId,
                                struct sockaddr_un* p_addr, socklen_t* alen) {
  mock_function_count_map[__func__]++;
  return 0;
}

size_t ringbuffer_available(const ringbuffer_t* rb) {
  mock_function_count_map[__func__]++;
  return 0;
}
size_t ringbuffer_delete(ringbuffer_t* rb, size_t length) {
  mock_function_count_map[__func__]++;
  return 0;
}
size_t ringbuffer_insert(ringbuffer_t* rb, const uint8_t* p, size_t length) {
  mock_function_count_map[__func__]++;
  return 0;
}
size_t ringbuffer_peek(const ringbuffer_t* rb, off_t offset, uint8_t* p,
                       size_t length) {
  mock_function_count_map[__func__]++;
  return 0;
}
size_t ringbuffer_pop(ringbuffer_t* rb, uint8_t* p, size_t length) {
  mock_function_count_map[__func__]++;
  return 0;
}
size_t ringbuffer_size(const ringbuffer_t* rb) {
  mock_function_count_map[__func__]++;
  return 0;
}
void ringbuffer_free(ringbuffer_t* rb) { mock_function_count_map[__func__]++; }

bool osi_property_get_bool(const char* key, bool default_value) {
  mock_function_count_map[__func__]++;
  return false;
}
int osi_property_get(const char* key, char* value, const char* default_value) {
  mock_function_count_map[__func__]++;
  return 0;
}
int osi_property_set(const char* key, const char* value) {
  mock_function_count_map[__func__]++;
  return 0;
}
int32_t osi_property_get_int32(const char* key, int32_t default_value) {
  mock_function_count_map[__func__]++;
  return 0;
}

bool semaphore_try_wait(semaphore_t* semaphore) {
  mock_function_count_map[__func__]++;
  return false;
}
int semaphore_get_fd(const semaphore_t* semaphore) {
  mock_function_count_map[__func__]++;
  return 0;
}
semaphore_t* semaphore_new(unsigned int value) {
  mock_function_count_map[__func__]++;
  return nullptr;
}
void semaphore_free(semaphore_t* semaphore) {
  mock_function_count_map[__func__]++;
}
void semaphore_post(semaphore_t* semaphore) {
  mock_function_count_map[__func__]++;
}
void semaphore_wait(semaphore_t* semaphore) {
  mock_function_count_map[__func__]++;
}

bool wakelock_acquire(void) {
  mock_function_count_map[__func__]++;
  return false;
}
bool wakelock_release(void) {
  mock_function_count_map[__func__]++;
  return false;
}
void wakelock_cleanup(void) { mock_function_count_map[__func__]++; }
void wakelock_debug_dump(int fd) { mock_function_count_map[__func__]++; }
void wakelock_set_os_callouts(bt_os_callouts_t* callouts) {
  mock_function_count_map[__func__]++;
}
void wakelock_set_paths(const char* lock_path, const char* unlock_path) {
  mock_function_count_map[__func__]++;
}
