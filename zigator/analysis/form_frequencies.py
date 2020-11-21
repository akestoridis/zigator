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


INCLUDED_COLUMNS = set([
    "phy_length",
    "mac_framepending",
    "mac_ackreq",
    "mac_panidcomp",
    "mac_dstaddrmode",
    "mac_srcaddrmode",
    "nwk_discroute",
    "nwk_multicast",
    "nwk_srcroute",
    "nwk_extendeddst",
    "nwk_extendedsrc",
    "nwk_edinitiator",
    "nwk_radius",
    "nwk_aux_extnonce",
])

INSPECTED_COLUMNS = [column_name for column_name in config.db.PKT_COLUMN_NAMES
                     if column_name in INCLUDED_COLUMNS]

PACKET_TYPES = [
    (
        "mac_acknowledgment.tsv",
        (
            ("error_msg", None),
            ("mac_frametype", "0b010: MAC Acknowledgment"),
        ),
    ),
    (
        "mac_beacon.tsv",
        (
            ("error_msg", None),
            ("mac_frametype", "0b000: MAC Beacon"),
        ),
    ),
    (
        "mac_assocreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x01: MAC Association Request"),
        ),
    ),
    (
        "mac_assocrsp.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x02: MAC Association Response"),
        ),
    ),
    (
        "mac_disassoc.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x03: MAC Disassociation Notification"),
        ),
    ),
    (
        "mac_datareq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x04: MAC Data Request"),
        ),
    ),
    (
        "mac_conflictnotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x05: MAC PAN ID Conflict Notification"),
        ),
    ),
    (
        "mac_orphannotif.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x06: MAC Orphan Notification"),
        ),
    ),
    (
        "mac_beaconreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x07: MAC Beacon Request"),
        ),
    ),
    (
        "mac_realign.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x08: MAC Coordinator Realignment"),
        ),
    ),
    (
        "mac_gtsreq.tsv",
        (
            ("error_msg", None),
            ("mac_cmd_id", "0x09: MAC GTS Request"),
        ),
    ),
    (
        "nwk_routerequest.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x01: NWK Route Request"),
        ),
    ),
    (
        "nwk_routereply.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x02: NWK Route Reply"),
        ),
    ),
    (
        "nwk_networkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x03: NWK Network Status"),
        ),
    ),
    (
        "nwk_leave.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x04: NWK Leave"),
        ),
    ),
    (
        "nwk_routerecord.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x05: NWK Route Record"),
        ),
    ),
    (
        "nwk_rejoinreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x06: NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_rejoinrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x07: NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_linkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x08: NWK Link Status"),
        ),
    ),
    (
        "nwk_networkreport.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x09: NWK Network Report"),
        ),
    ),
    (
        "nwk_networkupdate.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0a: NWK Network Update"),
        ),
    ),
    (
        "nwk_edtimeoutreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0b: NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_edtimeoutrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "0x0c: NWK End Device Timeout Response"),
        ),
    ),
    (
        "aps_acknowledgment.tsv",
        (
            ("error_msg", None),
            ("aps_frametype", "0b10: APS Acknowledgment"),
        ),
    ),
    (
        "aps_transportkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x05: APS Transport Key"),
        ),
    ),
    (
        "aps_updatedevice.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x06: APS Update Device"),
        ),
    ),
    (
        "aps_removedevice.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x07: APS Remove Device"),
        ),
    ),
    (
        "aps_requestkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x08: APS Request Key"),
        ),
    ),
    (
        "aps_switchkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x09: APS Switch Key"),
        ),
    ),
    (
        "aps_tunnel.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x0e: APS Tunnel"),
        ),
    ),
    (
        "aps_verifykey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x0f: APS Verify Key"),
        ),
    ),
    (
        "aps_confirmkey.tsv",
        (
            ("error_msg", None),
            ("aps_cmd_id", "0x10: APS Confirm Key"),
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

        # Compute the distinct matching values of the inspected columns
        form_values = config.db.fetch_values(
            INSPECTED_COLUMNS,
            conditions,
            True)
        form_values.sort(key=config.custom_sorter)

        # Compute the matching frequency for each form
        results = []
        for form_value in form_values:
            form_conditions = list(conditions)
            for i in range(len(form_value)):
                form_conditions.append((INSPECTED_COLUMNS[i], form_value[i]))
            matches = config.db.matching_frequency(form_conditions)
            results.append((form_value, matches))

        # Write the frequency of each form in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()


def form_frequencies(db_filepath, out_dirpath, num_workers):
    """Compute the frequency of forms for certain packet types."""
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
    logging.info("Computing the frequency of forms "
                 "for {} packet types using {} workers..."
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
