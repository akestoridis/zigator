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


def matching_frequencies(
    db_filepath,
    tablename,
    condition_matches,
    out_dirpath,
    num_workers,
):
    """Compute the matching frequency of certain conditions."""
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
    logging.info(
        "Computing the matching frequency "
        + "of {} conditions using {} workers...".format(
            len(condition_matches),
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
                condition_matches,
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
    condition_matches,
    out_dirpath,
    task_index,
    task_lock,
):
    # Connect to the provided database
    config.db.connect(db_filepath)

    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(condition_matches):
                condition_match = condition_matches[task_index.value]
                task_index.value += 1
            else:
                break

        # Derive the path of the output file, the varying columns,
        # and the matching conditions
        out_filepath = os.path.join(out_dirpath, condition_match[0])
        var_columns = condition_match[1]
        conditions = condition_match[2]

        # Compute the distinct values of the varying columns
        var_values = config.db.fetch_values(
            tablename,
            var_columns,
            conditions,
            True,
        )
        var_values.sort(key=config.custom_sorter)

        # Compute the matching frequency for each set of conditions
        results = []
        for var_value in var_values:
            var_conditions = list(conditions)
            for i in range(len(var_value)):
                var_conditions.append((var_columns[i], var_value[i]))
            matches = config.db.matching_frequency(tablename, var_conditions)
            results.append((var_value, matches))

        # Write the matching frequencies in the output file
        config.fs.write_tsv(results, out_filepath)

    # Disconnect from the provided database
    config.db.disconnect()
