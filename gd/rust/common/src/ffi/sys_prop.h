#include <string>
#include "rust/cxx.h"

namespace bluetooth {
namespace common {
namespace sys_prop {

rust::String get(rust::Str property);

}
}  // namespace common
}  // namespace bluetooth
