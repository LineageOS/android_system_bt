/******************************************************************************
 *
 *  Copyright 2020 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <functional>
#include <iterator>
#include <list>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <base/logging.h>

namespace bluetooth {

namespace common {

template <typename K, typename V>
class LruCache {
 public:
  using Node = std::pair<K, V>;
  using LruEvictionCallback = std::function<void(K, V)>;
  /**
   * Constructor of the cache
   *
   * @param capacity maximum size of the cache
   * @param log_tag, keyword to put at the head of log.
   * @param lru_eviction_callback a call back will be called when the cache is
   * full and Put() is called
   */
  LruCache(const size_t& capacity, const std::string& log_tag,
           LruEvictionCallback lru_eviction_callback)
      : capacity_(capacity), lru_eviction_callback_(lru_eviction_callback) {
    if (capacity_ == 0) {
      // don't allow invalid capacity
      LOG(FATAL) << log_tag << " unable to have 0 LRU Cache capacity";
    }
  }

  ~LruCache() { Clear(); }

  /**
   * Clear the cache
   */
  void Clear() {
    std::lock_guard<std::mutex> lock(lru_mutex_);
    lru_map_.clear();
    node_list_.clear();
  }

  /**
   * Get the value of a key, and move the key to the head of cache, if there is
   * one
   *
   * @param key
   * @param value, output parameter of value of the key
   * @return true if the cache has the key
   */
  bool Get(const K& key, V* value) {
    std::lock_guard<std::mutex> lock(lru_mutex_);
    auto map_iterator = lru_map_.find(key);
    if (map_iterator == lru_map_.end()) {
      return false;
    }
    auto& list_iterator = map_iterator->second;
    auto node = *list_iterator;
    node_list_.erase(list_iterator);
    node_list_.push_front(node);
    map_iterator->second = node_list_.begin();
    *value = node.second;
    return true;
  }

  /**
   * Check if the cache has the input key, move the key to the head
   * if there is one
   *
   * @param key
   * @return true if the cache has the key
   */
  bool HasKey(const K& key) {
    V dummy_value;
    return Get(key, &dummy_value);
  }

  /**
   * Put a key-value pair to the head of cache
   *
   * @param key
   * @param value
   * @return true if tail value is popped
   */
  bool Put(const K& key, const V& value) {
    if (HasKey(key)) {
      // hasKey() calls get(), therefore already move the node to the head
      std::lock_guard<std::mutex> lock(lru_mutex_);
      lru_map_[key]->second = value;
      return false;
    }

    bool value_popped = false;
    std::lock_guard<std::mutex> lock(lru_mutex_);
    // remove tail
    if (lru_map_.size() == capacity_) {
      lru_map_.erase(node_list_.back().first);
      K key_evicted = node_list_.back().first;
      V value_evicted = node_list_.back().second;
      node_list_.pop_back();
      lru_eviction_callback_(key_evicted, value_evicted);
      value_popped = true;
    }
    // insert to dummy next;
    Node add(key, value);
    node_list_.push_front(add);
    lru_map_[key] = node_list_.begin();
    return value_popped;
  }

  /**
   * Delete a key from cache
   *
   * @param key
   * @return true if delete successfully
   */
  bool Remove(const K& key) {
    std::lock_guard<std::mutex> lock(lru_mutex_);
    if (lru_map_.count(key) == 0) {
      return false;
    }

    // remove from the list
    auto& iterator = lru_map_[key];
    node_list_.erase(iterator);

    // delete key from map
    lru_map_.erase(key);

    return true;
  }

  /**
   * Return size of the cache
   *
   * @return size of the cache
   */
  int Size() const {
    std::lock_guard<std::mutex> lock(lru_mutex_);
    return lru_map_.size();
  }

 private:
  std::list<Node> node_list_;
  size_t capacity_;
  std::unordered_map<K, typename std::list<Node>::iterator> lru_map_;
  LruEvictionCallback lru_eviction_callback_;
  mutable std::mutex lru_mutex_;

  // delete copy constructor
  LruCache(LruCache const&) = delete;
  LruCache& operator=(LruCache const&) = delete;
};

}  // namespace common
}  // namespace bluetooth
