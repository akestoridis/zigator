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


def form_frequencies(
    db_filepath,
    tablename,
    packets_column_names,
    included_columns,
    packet_types,
    out_dirpath,
    num_workers,
):
    """Compute the frequency of forms for certain packet types."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Construct the list of columns that will be inspected
    inspected_columns = [
        column_name
        for column_name in packets_column_names
        if column_name in included_columns
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
        "Computing the frequency of forms "
        + "for {} packet types using {} workers...".format(
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

        # Compute the distinct matching values of the inspected columns
        form_values = config.db.fetch_values(
            tablename,
            inspected_columns,
            conditions,
            True,
        )
        form_values.sort(key=config.custom_sorter)

        # Compute the matching frequency for each form
        results = []
        for form_value in form_values:
            form_conditions = list(conditions)
            for i in range(len(form_value)):
                form_conditions.append((inspected_columns[i], form_value[i]))
            matches = config.db.matching_frequency(tablename, form_conditions)
            results.append((form_value, matches))

        # Write the frequency of each form in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()
