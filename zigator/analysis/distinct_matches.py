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


COLUMN_MATCHES = [
    (
        "phy_length--frametype.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "phy_length--frametype_cmdid.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "phy_length--nwk_cmd_id.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--phy_length.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "phy_length",
    ),
    (
        "nwk_radius--frametype.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_radius--frametype_cmdid.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_radius--nwk_cmd_id.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_radius.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_radius",
    ),
    (
        "mac_framepending--frametype.tsv",
        (
            "mac_framepending",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "mac_framepending--frametype_cmdid.tsv",
        (
            "mac_framepending",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_framepending--nwk_cmd_id.tsv",
        (
            "mac_framepending",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_framepending.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "mac_framepending",
    ),
    (
        "mac_ackreq--frametype.tsv",
        (
            "mac_ackreq",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "mac_ackreq--frametype_cmdid.tsv",
        (
            "mac_ackreq",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_ackreq--nwk_cmd_id.tsv",
        (
            "mac_ackreq",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_ackreq.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "mac_ackreq",
    ),
    (
        "mac_dstaddrmode--frametype.tsv",
        (
            "mac_dstaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "mac_dstaddrmode--frametype_cmdid.tsv",
        (
            "mac_dstaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_dstaddrmode--nwk_cmd_id.tsv",
        (
            "mac_dstaddrmode",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_dstaddrmode.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "mac_dstaddrmode",
    ),
    (
        "mac_srcaddrmode--frametype.tsv",
        (
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "mac_srcaddrmode--frametype_cmdid.tsv",
        (
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "mac_srcaddrmode--nwk_cmd_id.tsv",
        (
            "mac_srcaddrmode",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--mac_srcaddrmode.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "mac_srcaddrmode",
    ),
    (
        "nwk_srcroute--frametype.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_srcroute--frametype_cmdid.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_srcroute--nwk_cmd_id.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_srcroute.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_srcroute",
    ),
    (
        "nwk_extendeddst--frametype.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_extendeddst--frametype_cmdid.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_extendeddst--nwk_cmd_id.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_extendeddst.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_extendeddst",
    ),
    (
        "nwk_extendedsrc--frametype.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_extendedsrc--frametype_cmdid.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "nwk_extendedsrc--nwk_cmd_id.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_extendedsrc.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_extendedsrc",
    ),
    (
        "nwk_security--nwk_cmd_id.tsv",
        (
            "nwk_security",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_security.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_security",
    ),
    (
        "aps_ackreq--frametype.tsv",
        (
            "aps_ackreq",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "aps_ackreq--frametype_cmdid.tsv",
        (
            "aps_ackreq",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "aps_aux_keytype--frametype.tsv",
        (
            "aps_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "aps_aux_keytype--frametype_cmdid.tsv",
        (
            "aps_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "aps_aux_extnonce--frametype.tsv",
        (
            "aps_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "aps_aux_extnonce--frametype_cmdid.tsv",
        (
            "aps_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "security--frametype.tsv",
        (
            "mac_security",
            "nwk_security",
            "aps_security",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "security--frametype_cmdid.tsv",
        (
            "mac_security",
            "nwk_security",
            "aps_security",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "srcpanid--mac_frametype_cmdid.tsv",
        (
            "mac_srcpanid",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
    ),
    (
        "mac_frametype_cmdid--addrmode.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
        ),
        (
            ("error_msg", None),
        ),
        "mac_dstaddrmode",
        "mac_srcaddrmode",
    ),
    (
        "nwk_frametype_cmdid--addrmode.tsv",
        (
            "nwk_frametype",
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "nwk_extendeddst",
        "nwk_extendedsrc",
    ),
    (
        "nwk_srcshortaddr--nwk_cmdid.tsv",
        (
            "nwk_srcshortaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_dstshortaddr--nwk_cmdid.tsv",
        (
            "nwk_dstshortaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_srcextendedaddr--nwk_cmdid.tsv",
        (
            "nwk_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("!nwk_srcextendedaddr", None),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_dstextendedaddr--nwk_cmdid.tsv",
        (
            "nwk_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("!nwk_dstextendedaddr", None),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_srcextendedaddr--aps_frametype_cmdid.tsv",
        (
            "nwk_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
            ("!nwk_srcextendedaddr", None),
        ),
        "aps_frametype",
        "aps_cmd_id",
    ),
    (
        "nwk_dstextendedaddr--aps_frametype_cmdid.tsv",
        (
            "nwk_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
            ("!nwk_dstextendedaddr", None),
        ),
        "aps_frametype",
        "aps_cmd_id",
    ),
    (
        "mac_srcextendedaddr--mac_cmd_id.tsv",
        (
            "mac_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "mac_srcshortaddr--mac_cmd_id.tsv",
        (
            "mac_srcshortaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "mac_dstextendedaddr--mac_cmd_id.tsv",
        (
            "mac_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "mac_dstshortaddr--mac_cmd_id.tsv",
        (
            "mac_dstshortaddr",
        ),
        (
            ("error_msg", None),
            ("!mac_cmd_id", None),
        ),
        "mac_cmd_id",
    ),
    (
        "nwk_cmd_payloadlength--nwk_cmd_id.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--nwk_cmd_payloadlength.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_payloadlength",
    ),
    (
        "der_nwk_dsttype--nwk_cmd_id.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--der_nwk_dsttype.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "der_nwk_dsttype",
    ),
    (
        "der_nwk_srctype--nwk_cmd_id.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--der_nwk_srctype.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "der_nwk_srctype",
    ),
]


def worker(db_filepath, out_dirpath, task_index, task_lock):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(COLUMN_MATCHES):
                column_match = COLUMN_MATCHES[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file, the varying columns,
        # the matching conditions, and the list of column names
        out_filepath = os.path.join(out_dirpath, column_match[0])
        var_columns = column_match[1]
        conditions = column_match[2]
        column_names = list(column_match[3:])

        # Compute the distinct values of the varying columns
        var_values = config.db.fetch_values(
            var_columns,
            conditions,
            True)
        var_values.sort(key=config.custom_sorter)

        # Fetch the distinct values with the listed columns
        fetched_tuples = config.db.fetch_values(
            list(var_columns) + column_names,
            conditions,
            True)

        # Compute the distinct matches for each value
        distinct_matches = [set() for _ in range(len(var_values))]
        for fetched_tuple in fetched_tuples:
            var_value = fetched_tuple[:len(var_columns)]
            mat_value = fetched_tuple[len(var_columns):]
            distinct_matches[var_values.index(var_value)].add(mat_value)
        results = []
        for i in range(len(var_values)):
            matches = list(distinct_matches[i])
            matches.sort(key=config.custom_sorter)
            results.append((var_values[i], matches))

        # Write the distinct matches in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()


def distinct_matches(db_filepath, out_dirpath, num_workers):
    """Compute the distinct matching values for certain conditions."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Determine the number of processes that will be used
    if num_workers is None:
        if hasattr(os, "sched_getaffinity"):
            num_workers = len(os.sched_getaffinity(0)) - 1
        else:
            num_workers = mp.cpu_count() - 1
    if num_workers < 1:
        num_workers = 1
    logging.info("Computing the distinct matching values "
                 "for {} conditions using {} workers..."
                 "".format(len(COLUMN_MATCHES), num_workers))

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
