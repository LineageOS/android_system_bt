//! BT snoop logger

use bt_common::sys_prop;
use gddi::Stoppable;

/// The different modes snoop logging can be in
#[derive(Clone)]
pub enum SnoopMode {
    /// All logs disabled
    Disabled,
    /// Only sanitized logs
    Filtered,
    /// Log everything
    Full,
}

/// There was an error parsing the mode from a string
pub struct SnoopModeParseError;

impl std::str::FromStr for SnoopMode {
    type Err = SnoopModeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(SnoopMode::Disabled),
            "filtered" => Ok(SnoopMode::Filtered),
            "full" => Ok(SnoopMode::Full),
            _ => Err(SnoopModeParseError),
        }
    }
}

/// All snoop logging config
#[derive(Clone, Stoppable)]
pub struct SnoopConfig {
    path: String,
    max_packets_per_file: u32,
    mode: SnoopMode,
}

impl SnoopConfig {
    /// Constructs a new snoop config
    pub fn new() -> Self {
        Self {
            path: "/data/misc/bluetooth/logs/btsnoop_hci.log".to_string(),
            max_packets_per_file: sys_prop::get_u32("persist.bluetooth.btsnoopsize")
                .unwrap_or(0xFFFF),
            mode: get_configured_snoop_mode()
                .parse()
                .unwrap_or(SnoopMode::Disabled),
        }
    }

    /// Overwrites the laoded log path with the provided one
    pub fn set_path(&mut self, value: String) {
        self.path = value;
    }

    /// Overwrites the loaded mode with the provided one
    pub fn set_mode(&mut self, value: SnoopMode) {
        self.mode = value;
    }
}

impl Default for SnoopConfig {
    fn default() -> Self {
        Self::new()
    }
}

fn get_configured_snoop_mode() -> String {
    sys_prop::get("persist.bluetooth.btsnooplogmode").unwrap_or(if sys_prop::get_debuggable() {
        sys_prop::get("persist.bluetooth.btsnoopdefaultmode").unwrap_or_default()
    } else {
        String::default()
    })
}
