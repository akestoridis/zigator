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


COLUMN_GROUPS = [
    (
        "security-frequency.tsv",
        "mac_security",
        "nwk_security",
        "aps_security",
    ),
    (
        "keytype-frequency.tsv",
        "nwk_aux_keytype",
        "aps_aux_keytype",
    ),
    (
        "frametype-frequency.tsv",
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profile_id",
        "zcl_frametype",
    ),
    (
        "frametype_cmdid-frequency.tsv",
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profile_id",
        "aps_cluster_id",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "profileid_clusterid-frequency.tsv",
        "aps_profile_id",
        "aps_cluster_id",
    ),
    (
        "nwkcmdid_addrtype-frequency.tsv",
        "nwk_cmd_id",
        "der_nwk_dsttype",
        "der_nwk_srctype",
    ),
]


def worker(db_filepath, out_dirpath, task_index, task_lock):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(COLUMN_GROUPS):
                column_group = COLUMN_GROUPS[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file and the list of column names
        out_filepath = os.path.join(out_dirpath, column_group[0])
        column_names = column_group[1:]

        # Do not count entries with errors,
        # except when we want to count the errors themselves
        if "error_msg" in column_names:
            count_errors = True
        else:
            count_errors = False
        results = config.db.grouped_count(column_names, count_errors)

        # Write the computed frequencies in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()


def group_frequencies(db_filepath, out_dirpath, num_workers):
    """Compute the frequency of values for certain column groups."""
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
    logging.info("Computing the frequency of values "
                 "for {} column groups using {} workers..."
                 "".format(len(COLUMN_GROUPS), num_workers))

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
