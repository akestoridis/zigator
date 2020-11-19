# Copyright (C) 2020 Dimitrios-Georgios Akestoridis
#
# This file is part of Zigator.
#
# Zigator is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# Zigator is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Zigator. If not, see <https://www.gnu.org/licenses/>.

import logging
import multiprocessing as mp
import os

from .. import config


CONDITION_SELECTIONS = [
    (
        "packet_types.tsv",
        (
            "MAC Acknowledgment",
            ("error_msg", None),
            ("mac_frametype", "0b010: MAC Acknowledgment"),
        ),
        (
            "MAC Beacon",
            ("error_msg", None),
            ("mac_frametype", "0b000: MAC Beacon"),
        ),
        (
            "MAC Command",
            ("error_msg", None),
            ("mac_frametype", "0b011: MAC Command"),
        ),
        (
            "NWK Command",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
        ),
        (
            "APS Acknowledgment",
            ("error_msg", None),
            ("aps_frametype", "APS Acknowledgment"),
        ),
        (
            "APS Command",
            ("error_msg", None),
            ("aps_frametype", "APS Command"),
        ),
        (
            "ZDP Command",
            ("error_msg", None),
            ("aps_frametype", "APS Data"),
            ("aps_profilename", "Zigbee Device Profile (ZDP)"),
        ),
        (
            "ZCL Command",
            ("error_msg", None),
            ("aps_frametype", "APS Data"),
            ("!aps_profilename", "Zigbee Device Profile (ZDP)"),
        ),
    ),
    (
        "encrypted_nwk_commands.tsv",
        (
            "NWK Route Request",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
        (
            "NWK Route Reply",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
        (
            "NWK Network Status",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
        (
            "NWK Leave",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
        (
            "NWK Route Record",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
        (
            "NWK Rejoin Request",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
        (
            "NWK Rejoin Response",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
        (
            "NWK Link Status",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
        (
            "NWK Network Report",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
        (
            "NWK Network Update",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
        (
            "NWK End Device Timeout Request",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
        (
            "NWK End Device Timeout Response",
            ("error_msg", None),
            ("nwk_frametype", "0b01: NWK Command"),
            ("nwk_security", "0b1: NWK Security Enabled"),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "datarequest--srcaddrmode.tsv",
        (
            "MAC Data Request with short source address",
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b10: Short source MAC address"),
        ),
        (
            "MAC Data Request with extended source address",
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
            ("mac_srcaddrmode", "0b11: Extended source MAC address"),
        ),
    ),
]


def worker(db_filepath, out_dirpath, task_index, task_lock):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(CONDITION_SELECTIONS):
                condition_selection = CONDITION_SELECTIONS[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file and the selected conditions
        out_filepath = os.path.join(out_dirpath, condition_selection[0])
        selections = condition_selection[1:]

        # Compute the matching frequency of each selection
        results = []
        for selection in selections:
            name = selection[0]
            conditions = selection[1:]
            matches = config.db.matching_frequency(conditions)
            results.append((name, matches))

        # Write the matching frequencies in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()


def selected_frequencies(db_filepath, out_dirpath, num_workers):
    """Compute the frequency of selected conditions."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Determine the number of processes that will be used
    if num_workers is None:
        if hasattr(os, "sched_getaffinity"):
            num_workers = len(os.sched_getaffinity(0))
        else:
            num_workers = mp.cpu_count()
    if num_workers < 1:
        num_workers = 1
    logging.info("Computing the frequency of "
                 "{} condition selections using {} workers..."
                 "".format(len(CONDITION_SELECTIONS), num_workers))

    # Create variables that will be shared by the processes
    task_index = mp.Value("L", 0, lock=False)
    task_lock = mp.Lock()

    # Start the processes
    processes = []
    for _ in range(num_workers):
        p = mp.Process(target=worker,
                       args=(db_filepath, out_dirpath, task_index, task_lock))
        p.start()
        processes.append(p)

    # Make sure that all processes terminated
    for p in processes:
        p.join()
    logging.info("All {} workers completed their tasks".format(num_workers))
