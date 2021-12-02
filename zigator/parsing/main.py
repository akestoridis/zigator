# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis
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
from glob import glob

from .. import config
from ..enums import Message
from .pcap_file import pcap_file


def main(pcap_dirpath, db_filepath, num_workers):
    """Parse all pcap files in the provided directory."""
    # Sanity check
    if not os.path.isdir(pcap_dirpath):
        raise ValueError(
            "The provided directory \"{}\" does not exist".format(
                pcap_dirpath,
            ),
        )

    # Initialize the database that will store the parsed data
    config.db.connect(db_filepath)
    config.db.create_table("packets")
    config.db.commit()

    # Get a sorted list of pcap filepaths
    filepaths = glob(
        os.path.join(pcap_dirpath, "**", "*.[pP][cC][aA][pP]"),
        recursive=True,
    )
    filepaths.sort()
    logging.info(
        "Detected {} pcap files in the \"{}\" directory".format(
            len(filepaths),
            pcap_dirpath,
        ),
    )

    # Determine the number of processes that will be used
    if num_workers is None:
        if hasattr(os, "sched_getaffinity"):
            num_workers = len(os.sched_getaffinity(0)) - 1
        else:
            num_workers = mp.cpu_count() - 1
    if num_workers < 1:
        num_workers = 1
    logging.info(
        "The pcap files will be parsed by {} workers".format(num_workers),
    )

    # Create variables that will be shared by the processes
    msg_queue = mp.Queue()
    task_index = mp.Value("L", 0, lock=False)
    task_lock = mp.Lock()

    # Start the processes
    processes = []
    for _ in range(num_workers):
        p = mp.Process(
            target=worker,
            args=(filepaths, msg_queue, task_index, task_lock),
        )
        p.start()
        processes.append(p)

    # Process received messages until all the tasks are completed
    num_terminated_processes = 0
    pcap_counter = 0
    new_network_keys = 0
    new_link_keys = 0
    while num_terminated_processes < num_workers:
        msg_type, msg_obj = msg_queue.get()
        if msg_type == Message.RETURN:
            num_terminated_processes += 1
            logging.debug(
                "The process with ID {} ".format(msg_obj)
                + "has no more pcap files to parse",
            )
        elif msg_type == Message.DEBUG:
            logging.debug(msg_obj)
        elif msg_type == Message.INFO:
            logging.info(msg_obj)
        elif msg_type == Message.WARNING:
            logging.warning(msg_obj)
        elif msg_type == Message.ERROR:
            logging.error(msg_obj)
        elif msg_type == Message.CRITICAL:
            logging.critical(msg_obj)
        elif msg_type == Message.PCAP:
            pcap_counter += 1
            logging.info(
                "Parsed {} out of the {} pcap files".format(
                    pcap_counter,
                    len(filepaths),
                ),
            )
        elif msg_type == Message.PKT:
            config.db.insert("packets", msg_obj)
        elif msg_type == Message.NETWORK_KEYS:
            for key_name in msg_obj.keys():
                if key_name not in config.network_keys.keys():
                    if msg_obj[key_name] not in config.network_keys.values():
                        config.network_keys[key_name] = msg_obj[key_name]
                        new_network_keys += 1
        elif msg_type == Message.LINK_KEYS:
            for key_name in msg_obj.keys():
                if key_name not in config.link_keys.keys():
                    if msg_obj[key_name] not in config.link_keys.values():
                        config.link_keys[key_name] = msg_obj[key_name]
                        new_link_keys += 1
        elif msg_type == Message.NETWORKS:
            for panid in msg_obj.keys():
                config.update_networks(
                    panid,
                    msg_obj[panid]["epidset"],
                    msg_obj[panid]["earliest"],
                    msg_obj[panid]["latest"],
                )
        elif msg_type == Message.SHORT_ADDRESSES:
            for (panid, shortaddr) in msg_obj.keys():
                config.update_short_addresses(
                    panid,
                    shortaddr,
                    msg_obj[(panid, shortaddr)]["altset"],
                    msg_obj[(panid, shortaddr)]["macset"],
                    msg_obj[(panid, shortaddr)]["nwkset"],
                    msg_obj[(panid, shortaddr)]["earliest"],
                    msg_obj[(panid, shortaddr)]["latest"],
                )
        elif msg_type == Message.EXTENDED_ADDRESSES:
            for extendedaddr in msg_obj.keys():
                config.update_extended_addresses(
                    extendedaddr,
                    msg_obj[extendedaddr]["altset"],
                    msg_obj[extendedaddr]["macset"],
                    msg_obj[extendedaddr]["nwkset"],
                    msg_obj[extendedaddr]["earliest"],
                    msg_obj[extendedaddr]["latest"],
                )
        elif msg_type == Message.PAIRS:
            for (panid, srcaddr, dstaddr) in msg_obj.keys():
                config.update_pairs(
                    panid,
                    srcaddr,
                    dstaddr,
                    msg_obj[(panid, srcaddr, dstaddr)]["earliest"],
                    msg_obj[(panid, srcaddr, dstaddr)]["latest"],
                )
        else:
            raise ValueError("Unknown message type \"{}\"".format(msg_type))

    # Make sure that all processes terminated
    for p in processes:
        p.join()
    logging.info("All {} workers completed their tasks".format(num_workers))

    # Make sure that the message queue is empty
    if not msg_queue.empty():
        raise ValueError("Expected the message queue to be empty")

    # Commit the received data to the database
    config.db.commit()

    # Log a summary of new keys and derived information
    logging.info(
        "Discovered {} previously unknown network keys".format(
            new_network_keys,
        ),
    )
    logging.info(
        "Discovered {} previously unknown link keys".format(new_link_keys),
    )
    logging.info(
        "Discovered {} pairs of network identifiers".format(
            len(config.networks.keys()),
        ),
    )
    logging.info(
        "Discovered {} PAN ID and short address pairs".format(
            len(config.short_addresses.keys()),
        ),
    )
    logging.info(
        "Discovered {} extended addresses".format(
            len(config.extended_addresses.keys()),
        ),
    )
    logging.info(
        "Discovered {} source-destination pairs of MAC Data packets".format(
            len(config.pairs.keys()),
        ),
    )

    # Update the packets table using the derived information
    logging.info("Updating the derived entries of parsed packets...")
    config.update_derived_entries()
    logging.info("Finished updating the derived entries of parsed packets")

    # Store the derived information into the database
    config.db.store_networks(config.networks)
    config.db.store_short_addresses(config.short_addresses)
    config.db.store_extended_addresses(config.extended_addresses)
    config.db.store_pairs(config.pairs)
    config.db.commit()

    # Log a summary of the generated warnings
    warnings = config.db.fetch_values("packets", ["warning_msg"], None, True)
    warnings.sort(key=config.custom_sorter)
    for warning in warnings:
        message = warning[0]
        if message is None:
            continue
        frequency = config.db.matching_frequency(
            "packets",
            [("warning_msg", message)],
        )
        logging.warning(
            "Generated {} \"{}\" parsing warnings".format(frequency, message),
        )

    # Log a summary of the generated errors
    errors = config.db.fetch_values("packets", ["error_msg"], None, True)
    errors.sort(key=config.custom_sorter)
    for error in errors:
        message = error[0]
        if message is None:
            continue
        frequency = config.db.matching_frequency(
            "packets",
            [("error_msg", message)],
        )
        logging.warning(
            "Generated {} \"{}\" parsing errors".format(frequency, message),
        )

    # Disconnect from the database
    config.db.disconnect()


def worker(filepaths, msg_queue, task_index, task_lock):
    """Parse pcap files from the task list."""
    while True:
        with task_lock:
            if task_index.value < len(filepaths):
                filepath = filepaths[task_index.value]
                task_index.value += 1
            else:
                break
        pcap_file(filepath, msg_queue)
        msg_queue.put((Message.PCAP, filepath))
    msg_queue.put((Message.RETURN, os.getpid()))
