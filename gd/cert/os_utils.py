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

import logging
from pathlib import Path
import psutil
import subprocess
from typing import Container


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


def make_ports_available(ports: Container[int], timeout_seconds=10):
    """Make sure a list of ports are available
    kill occupying process if possible
    :param ports: list of target ports
    :param timeout_seconds: number of seconds to wait when killing processes
    :return: True on success, False on failure
    """
    if not ports:
        logging.warning("Empty ports is given to make_ports_available()")
        return True
    # Get connections whose state are in LISTEN only
    # Connections in other states won't affect binding as SO_REUSEADDR is used
    listening_conns_for_port = filter(
        lambda conn: (conn and conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port in ports),
        psutil.net_connections())
    success = True
    for conn in listening_conns_for_port:
        logging.warning(
            "Freeing port %d used by %s" % (conn.laddr.port, str(conn)))
        if not conn.pid:
            logging.error(
                "Failed to kill process occupying port %d due to lack of pid" %
                conn.laddr.port)
            success = False
            continue
        logging.warning("Killing pid %d that is using port port %d" %
                        (conn.pid, conn.laddr.port))
        process = psutil.Process(conn.pid)
        process.kill()
        try:
            process.wait(timeout=timeout_seconds)
        except psutil.TimeoutExpired:
            logging.error("SIGKILL timeout after %d seconds for pid %d" %
                          (timeout_seconds, conn.pid))
            continue
    return success
