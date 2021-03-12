//
//  Copyright 2021 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let gd_root = match env::var("PLATFORM_SUBDIR") {
        Ok(dir) => PathBuf::from(dir).join("bt/gd"),
        // Currently at //platform2/gd/rust/rust/packets
        Err(_) => PathBuf::from(env::current_dir().unwrap()).join("../..").canonicalize().unwrap(),
    };

    let input_files = [gd_root.join("hci/hci_packets.pdl")];
    let outputted = [out_dir.join("../../hci/hci_packets.rs")];

    // Find the packetgen tool. Expecting it at CARGO_HOME/bin
    let packetgen =
        PathBuf::from(env::var("CARGO_HOME").unwrap()).join("bin").join("bluetooth_packetgen");

    for i in 0..input_files.len() {
        let output = Command::new(packetgen.as_os_str().to_str().unwrap())
            .arg("--source_root=".to_owned() + gd_root.as_os_str().to_str().unwrap())
            .arg("--out=".to_owned() + out_dir.as_os_str().to_str().unwrap())
            .arg("--include=bt/gd")
            .arg("--rust")
            .arg(input_files[i].as_os_str().to_str().unwrap())
            .output()
            .unwrap();

        println!(
            "Status: {}, stdout: {}, stderr: {}",
            output.status,
            String::from_utf8_lossy(output.stdout.as_slice()),
            String::from_utf8_lossy(output.stderr.as_slice())
        );

        // File will be at ${OUT_DIR}/../../${input_files[i].strip('.pdl')}.rs
        std::fs::rename(
            outputted[i].as_os_str().to_str().unwrap(),
            out_dir.join(outputted[i].file_name().unwrap()).as_os_str().to_str().unwrap(),
        )
        .unwrap();
    }
}
