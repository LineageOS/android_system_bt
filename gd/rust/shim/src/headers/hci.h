#pragma once
#include "src/hci.rs.h"

namespace bluetooth {
namespace shim {
namespace rust {
void hci_on_acl(::rust::Slice<uint8_t> data);
void hci_on_event(::rust::Slice<uint8_t> data);
void hci_on_le_event(::rust::Slice<uint8_t> data);
}  // namespace rust
}  // namespace shim
}  // namespace bluetooth
