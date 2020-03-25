#!/usr/bin/env python3
#
#   Copyright 2020 - The Android Open Source Project
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from pathlib import Path
import subprocess


def is_subprocess_alive(process, timeout_seconds=1):
    """
    Check if a process is alive for at least timeout_seconds
    :param process: a Popen object that represent a subprocess
    :param timeout_seconds: process needs to be alive for at least
           timeout_seconds
    :return: True if process is alive for at least timeout_seconds
    """
    try:
        process.wait(timeout=timeout_seconds)
        return False
    except subprocess.TimeoutExpired as exp:
        return True


def get_gd_root():
    """
    Return the root of the GD test library

    GD root is the parent directory of cert
    :return: root directory string of gd test library
    """
    return str(Path(__file__).absolute().parents[1])
