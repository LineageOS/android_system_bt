#pragma once

#include "base/callback.h"
#include "rust/cxx.h"

namespace bluetooth {
namespace shim {
namespace rust {

class u8SliceCallback {
 public:
  u8SliceCallback(base::Callback<void(::rust::Slice<uint8_t>)> callback) : callback_(callback) {}

  void Run(::rust::Slice<uint8_t> value) const {
    callback_.Run(value);
  }

 private:
  base::Callback<void(::rust::Slice<uint8_t>)> callback_;
};

}  // namespace rust
}  // namespace shim
}  // namespace bluetooth

#include "src/hci.rs.h"
