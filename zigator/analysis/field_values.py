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


IGNORED_COLUMNS = set([
    "pkt_num",
    "pkt_time",
    "phy_payload",
    "mac_show",
    "mac_fcs",
    "mac_seqnum",
    "nwk_seqnum",
    "nwk_aux_framecounter",
    "nwk_aux_decpayload",
    "nwk_aux_decshow",
    "aps_counter",
    "apx_aux_framecounter",
    "aps_aux_decpayload",
    "aps_aux_decshow",
    "aps_tunnel_counter",
    "zdp_seqnum",
    "zcl_seqnum",
])

INSPECTED_COLUMNS = [column_name for column_name in config.db.PKT_COLUMN_NAMES
                     if column_name not in IGNORED_COLUMNS]

PACKET_TYPES = [
    (
        "nwk_routerequest.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_routereply.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_networkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_leave.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_routerecord.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_rejoinreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_rejoinrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_linkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_networkreport.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_networkupdate.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_edtimeoutreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_edtimeoutrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "mac_assocreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Association Request"),
        ),
    ),
    (
        "mac_assocrsp.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Association Response"),
        ),
    ),
    (
        "mac_disassoc.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Disassociation Notification"),
        ),
    ),
    (
        "mac_datareq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Data Request"),
        ),
    ),
    (
        "mac_conflictnotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC PAN ID Conflict Notification"),
        ),
    ),
    (
        "mac_orphannotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Orphan Notification"),
        ),
    ),
    (
        "mac_beaconreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Beacon Request"),
        ),
    ),
    (
        "mac_realign.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Coordinator Realignment"),
        ),
    ),
    (
        "mac_gtsreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC GTS Request"),
        ),
    ),
]


def worker(db_filepath, out_dirpath, task_index, task_lock):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(PACKET_TYPES):
                packet_type = PACKET_TYPES[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file and the matching conditions
        out_filepath = os.path.join(out_dirpath, packet_type[0])
        conditions = packet_type[1]

        # Fetch the distinct values of the inspected columns
        fetched_tuples = config.db.fetch_values(
            INSPECTED_COLUMNS,
            conditions,
            True)

        # Compute the distinct values of each column
        distinct_values = [set() for _ in range(len(INSPECTED_COLUMNS))]
        for fetched_tuple in fetched_tuples:
            for i in range(len(INSPECTED_COLUMNS)):
                distinct_values[i].add((fetched_tuple[i],))
        results = []
        for i in range(len(INSPECTED_COLUMNS)):
            var_values = list(distinct_values[i])
            var_values.sort(key=config.custom_sorter)
            var_values = [var_value[0] for var_value in var_values]
            results.append((INSPECTED_COLUMNS[i], var_values))

        # Write the distinct values of each column in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()


def field_values(db_filepath, out_dirpath, num_workers):
    """Compute the distinct field values of certain packet types."""
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
    logging.info("Computing the distinct field values "
                 "of {} packet types using {} workers..."
                 "".format(len(PACKET_TYPES), num_workers))

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
