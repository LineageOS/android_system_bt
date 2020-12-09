#include "sys_prop.h"
#include <cutils/properties.h>

namespace bluetooth {
namespace common {
namespace sys_prop {

rust::String get(rust::Str property) {
  auto name = std::string(property.data(), property.length());
  std::array<char, PROPERTY_VALUE_MAX> value_array{0};
  auto value_len = property_get(name.c_str(), value_array.data(), nullptr);
  if (value_len <= 0) {
    value_len = 0;
  }
  return rust::String(value_array.data(), value_len);
}

}  // namespace sys_prop
}  // namespace common
}  // namespace bluetooth
