# Copyright (C) 2020-2022 Dimitrios-Georgios Akestoridis
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


def solo_frequencies(
    db_filepath,
    tablename,
    packets_column_names,
    ignored_columns,
    out_dirpath,
    num_workers,
):
    """Compute the frequency of values for certain columns."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Construct the list of columns that will be inspected
    inspected_columns = [
        column_name
        for column_name in packets_column_names
        if column_name not in ignored_columns
    ]

    # Determine the number of processes that will be used
    if num_workers is None:
        if hasattr(os, "sched_getaffinity"):
            num_workers = len(os.sched_getaffinity(0))
        else:
            num_workers = mp.cpu_count()
    if num_workers < 1:
        num_workers = 1
    logging.info(
        "Computing the frequency of values "
        + "for {} columns using {} workers...".format(
            len(inspected_columns),
            num_workers,
        ),
    )

    # Create variables that will be shared by the processes
    task_index = mp.Value("L", 0, lock=False)
    task_lock = mp.Lock()

    # Start the processes
    processes = []
    for _ in range(num_workers):
        p = mp.Process(
            target=worker,
            args=(
                db_filepath,
                tablename,
                packets_column_names,
                inspected_columns,
                out_dirpath,
                task_index,
                task_lock,
            ),
        )
        p.start()
        processes.append(p)

    # Make sure that all processes terminated
    for p in processes:
        p.join()
    logging.info("All {} workers completed their tasks".format(num_workers))


def worker(
    db_filepath,
    tablename,
    packets_column_names,
    inspected_columns,
    out_dirpath,
    task_index,
    task_lock,
):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(inspected_columns):
                column_name = inspected_columns[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file
        global_index = packets_column_names.index(column_name)
        out_filepath = os.path.join(
            out_dirpath,
            "{}-{}-frequency.tsv".format(
                str(global_index).zfill(3),
                column_name,
            ),
        )

        # Do not count entries with errors,
        # except when we want to count the errors themselves
        results = config.db.grouped_count(
            tablename,
            [column_name],
            column_name == "error_msg",
        )

        # Write the computed frequencies in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()
