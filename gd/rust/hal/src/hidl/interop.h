#pragma once
#include "src/hidl_hal.rs.h"

namespace bluetooth {
namespace hal {

void start_hal();
void stop_hal();
void send_command(rust::Slice<uint8_t> data);
void send_acl(rust::Slice<uint8_t> data);
void send_sco(rust::Slice<uint8_t> data);

}  // namespace hal
}  // namespace bluetooth
