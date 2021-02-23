

#pragma once

#include <list>
#include <map>
#include <string>

#include "include/hardware/bluetooth.h"

using acl_state_changed_params_t = struct {
  bt_status_t status;
  RawAddress* remote_bd_addr;
  bt_acl_state_t state;
  bt_hci_error_code_t hci_reason;
};

using callback_params_t = union {
  acl_state_changed_params_t acl_state_changed;
};

using interface_data_t = struct {
  std::string name;
  callback_params_t params;
};

using callback_function_t = void (*)(interface_data_t);
using interface_callback_t = struct {
  std::string name;
  callback_function_t function;
};

void headless_add_callback(const std::string interface_name,
                           callback_function_t function);
void headless_remove_callback(const std::string interface_name,
                              callback_function_t function);
