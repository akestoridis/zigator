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
    "pkt_bytes",
    "pkt_show",
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


def worker(db_filepath, out_dirpath, task_index, task_lock):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(INSPECTED_COLUMNS):
                column_name = INSPECTED_COLUMNS[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file
        global_index = config.db.PKT_COLUMN_NAMES.index(column_name)
        out_filepath = os.path.join(out_dirpath, "{}-{}-frequency.tsv"
            "".format(str(global_index).zfill(3), column_name))

        # Do not count entries with errors,
        # except when we want to count the errors themselves
        if column_name == "error_msg":
            count_errors = True
        else:
            count_errors = False
        results = config.db.grouped_count([column_name], count_errors)

        # Write the computed frequencies in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()


def solo_frequencies(db_filepath, out_dirpath, num_workers):
    """Compute the frequency of values for certain columns."""
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
                 "for {} columns using {} workers..."
                 "".format(len(INSPECTED_COLUMNS), num_workers))

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
