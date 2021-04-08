#pragma once

#include "base/callback.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "rust/cxx.h"

namespace bluetooth {
namespace shim {
namespace rust {

template <class TArg>
class TrampolineCallback {
 public:
  TrampolineCallback(base::Callback<void(TArg)> callback) : callback_(callback) {}

  void Run(TArg value) const {
    callback_.Run(value);
  }

 private:
  base::Callback<void(TArg)> callback_;
};

template <class TArg>
class TrampolineOnceCallback {
 public:
  TrampolineOnceCallback(base::OnceCallback<void(TArg)> callback)
      : callback_(new base::OnceCallback<void(TArg)>(std::move(callback))) {}
  ~TrampolineOnceCallback() {
    if (callback_ != nullptr) {
      delete callback_;
      callback_ = nullptr;
    }
  }

  void Run(TArg value) const {
    std::move(*callback_).Run(value);
    delete callback_;
    ((TrampolineOnceCallback<TArg>*)this)->callback_ = nullptr;
  }

 private:
  base::OnceCallback<void(TArg)>* callback_;
};

class OnceClosure {
 public:
  OnceClosure(base::OnceClosure closure) : closure_(new base::OnceClosure(std::move(closure))) {}
  ~OnceClosure() {
    if (closure_ != nullptr) {
      delete closure_;
      closure_ = nullptr;
    }
  }

  void Run() const {
    std::move(*closure_).Run();
    delete closure_;
    ((OnceClosure*)this)->closure_ = nullptr;
  }

 private:
  base::OnceClosure* closure_;
};

using u8SliceCallback = TrampolineCallback<::rust::Slice<const uint8_t>>;
using u8SliceOnceCallback = TrampolineOnceCallback<::rust::Slice<const uint8_t>>;

}  // namespace rust
}  // namespace shim
}  // namespace bluetooth

#include "src/bridge.rs.h"
