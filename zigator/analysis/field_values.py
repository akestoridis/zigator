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


def field_values(
    db_filepath,
    tablename,
    packets_column_names,
    ignored_columns,
    packet_types,
    out_dirpath,
    num_workers,
):
    """Compute the distinct field values of certain packet types."""
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
        "Computing the distinct field values "
        + "of {} packet types using {} workers...".format(
            len(packet_types),
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
                inspected_columns,
                packet_types,
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
    inspected_columns,
    packet_types,
    out_dirpath,
    task_index,
    task_lock,
):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(packet_types):
                packet_type = packet_types[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file and the matching conditions
        out_filepath = os.path.join(out_dirpath, packet_type[0])
        conditions = packet_type[1]

        # Fetch the distinct values of the inspected columns
        fetched_tuples = config.db.fetch_values(
            tablename,
            inspected_columns,
            conditions,
            True,
        )

        # Compute the distinct values of each column
        tmp_sets = [set() for _ in range(len(inspected_columns))]
        for fetched_tuple in fetched_tuples:
            for i in range(len(inspected_columns)):
                tmp_sets[i].add((fetched_tuple[i],))
        results = []
        for i in range(len(inspected_columns)):
            var_values = list(tmp_sets[i])
            var_values.sort(key=config.custom_sorter)
            var_values = [var_value[0] for var_value in var_values]
            results.append((inspected_columns[i], var_values))

        # Write the distinct values of each column in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()
