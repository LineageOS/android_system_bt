/*
 * Copyright 2019 The Android Open Source Project
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

#include <iterator>
#include <sstream>
#include <string>
#include <vector>

class Size {
 public:
  Size() {}

  Size(int bits) {
    is_valid_ = true;
    bits_ = bits;
  }

  Size(std::string dynamic) {
    is_valid_ = true;
    dynamic_.push_back(dynamic);
  }

  Size(int bits, std::string dynamic) {
    is_valid_ = true;
    bits_ = bits;
    dynamic_.push_back(dynamic);
  }

  Size(const Size& size) {
    is_valid_ = size.is_valid_;
    bits_ = size.bits_;
    dynamic_ = size.dynamic_;
  }

  std::string dynamic_string() {
    if (dynamic_.empty()) return " 0 /* dynamic */ ";

    std::stringstream result;
    // Print everything but the last element then append it manually to avoid
    // the trailing "+" operator.
    std::copy(dynamic_.begin(), dynamic_.end() - 1, std::ostream_iterator<std::string>(result, " + "));
    result << dynamic_.back();
    return result.str();
  }

  std::vector<std::string> dynamic_string_list() {
    return dynamic_;
  }

  bool empty() {
    return !is_valid_;
  }

  bool has_bits() {
    return bits_ != 0;
  }

  bool has_dynamic() {
    return !dynamic_.empty();
  }

  int bits() {
    return bits_;
  }

  int bytes() {
    return bits_ / 8;
  }

  Size operator+(int rhs) {
    return Size(bits_ + rhs);
  }

  Size operator+(std::string rhs) {
    auto ret = Size();
    ret.is_valid_ = true;
    ret.dynamic_.insert(ret.dynamic_.end(), dynamic_.begin(), dynamic_.end());
    ret.dynamic_.push_back(rhs);
    return ret;
  }

  Size operator+(const Size& rhs) {
    auto ret = Size(bits_ += rhs.bits_);
    ret.is_valid_ = true;
    ret.dynamic_.insert(ret.dynamic_.end(), dynamic_.begin(), dynamic_.end());
    ret.dynamic_.insert(ret.dynamic_.end(), rhs.dynamic_.begin(), rhs.dynamic_.end());
    return ret;
  }

  Size& operator+=(int rhs) {
    is_valid_ = true;
    bits_ += rhs;
    return *this;
  }

  Size& operator+=(std::string rhs) {
    is_valid_ = true;
    dynamic_.push_back(rhs);
    return *this;
  }

  Size& operator+=(const Size& rhs) {
    is_valid_ = true;
    bits_ += rhs.bits_;
    dynamic_.insert(dynamic_.end(), rhs.dynamic_.begin(), rhs.dynamic_.end());
    return *this;
  }

  std::string ToString() {
    std::stringstream str;
    str << "Bits: " << bits_ << " | "
        << "Dynamic: " << dynamic_string();
    return str.str();
  }

 private:
  bool is_valid_ = false;
  int bits_ = 0;
  std::vector<std::string> dynamic_;
};
