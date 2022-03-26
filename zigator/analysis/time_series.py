# Copyright (C) 2022 Dimitrios-Georgios Akestoridis
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


def time_series(db_filepath, tablename, out_dirpath, num_workers):
    """Generate time series data from captured packets."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Connect to the provided database
    config.db.connect(db_filepath)

    # Fetch distinct and sorted pairs of pcap directories and filenames
    logging.info("Fetching information about distinct pcap files...")
    pcap_tuples = config.db.fetch_values(
        tablename,
        ["pcap_directory", "pcap_filename"],
        None,
        True,
        ["pcap_directory", "pcap_filename"],
    )

    # Determine the number of processes that will be used
    if num_workers is None:
        if hasattr(os, "sched_getaffinity"):
            num_workers = len(os.sched_getaffinity(0))
        else:
            num_workers = mp.cpu_count()
    if num_workers < 1:
        num_workers = 1
    logging.info(
        "Generating time series data from captured packets "
        + "that were in {} pcap files using {} workers...".format(
            len(pcap_tuples),
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
                pcap_tuples,
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
    pcap_tuples,
    out_dirpath,
    task_index,
    task_lock,
):
    # Connect to the provided database
    config.db.connect(db_filepath)

    pcap_id = 0
    while True:
        with task_lock:
            # Get the next task
            if task_index.value < len(pcap_tuples):
                pcap_directory, pcap_filename = pcap_tuples[task_index.value]
                task_index.value += 1
                pcap_id = task_index.value
            else:
                break

        # Fetch data about each packet that was in the provided pcap file,
        # sorted by packet time
        fetched_tuples = config.db.fetch_values(
            tablename,
            ["pkt_time"],
            [
                ("pcap_directory", pcap_directory),
                ("pcap_filename", pcap_filename),
            ],
            False,
            ["pkt_time"],
        )

        # Update the corresponding counters
        counters = {}
        min_pkt_time = None
        max_time_group = 0
        for fetched_tuple in fetched_tuples:
            pkt_time = fetched_tuple[0]

            if min_pkt_time is None:
                min_pkt_time = pkt_time

            time_group = int(pkt_time - min_pkt_time) + 1

            if time_group > max_time_group:
                max_time_group = time_group

            if time_group not in counters.keys():
                counters[time_group] = {
                    "capturedpackets": 1,
                }
            else:
                counters[time_group]["capturedpackets"] += 1

        # Derive the path of each output file
        out_capturedpackets_filepath = os.path.join(
            out_dirpath,
            "pcap{}--{}--capturedpacketspersecond.tsv".format(
                str(pcap_id).zfill(3),
                os.path.splitext(pcap_filename)[0],
            ),
        )

        # Generate the time series data
        results_capturedpackets = []
        for time_group in range(max_time_group + 1):
            if time_group not in counters.keys():
                results_capturedpackets.append((time_group, 0))
            else:
                results_capturedpackets.append(
                    (time_group, counters[time_group]["capturedpackets"]),
                )

        # Write the time series data in the corresponding output file
        config.fs.write_tsv(
            results_capturedpackets,
            out_capturedpackets_filepath,
        )

    # Disconnect from the provided database
    config.db.disconnect()
