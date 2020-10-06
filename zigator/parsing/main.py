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

import glob
import logging
import multiprocessing as mp
import os

from .. import config
from .pcap_file import pcap_file


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
        msg_queue.put((config.PCAP_MSG, filepath))
    msg_queue.put((config.RETURN_MSG, os.getpid()))


def main(pcap_dirpath, db_filepath, num_workers):
    """Parse all pcap files in the provided directory."""
    # Sanity check
    if not os.path.isdir(pcap_dirpath):
        raise ValueError("The provided directory \"{}\" "
                         "does not exist".format(pcap_dirpath))

    # Initialize the database that will store the parsed data
    config.db.connect(db_filepath)
    config.db.create_table("packets")
    config.db.commit()

    # Get a sorted list of pcap filepaths
    filepaths = glob.glob(
        os.path.join(pcap_dirpath, "**", "*.[pP][cC][aA][pP]"),
        recursive=True)
    filepaths.sort()
    logging.info("Detected {} pcap files in the \"{}\" directory"
                 "".format(len(filepaths), pcap_dirpath))

    # Determine the number of processes that will be used
    if num_workers is None:
        num_workers = len(os.sched_getaffinity(0)) - 1
    if num_workers < 1:
        num_workers = 1
    logging.info("The pcap files will be parsed by {} workers"
                 "".format(num_workers))

    # Create variables that will be shared by the processes
    msg_queue = mp.Queue()
    task_index = mp.Value("L", 0, lock=False)
    task_lock = mp.Lock()

    # Start the processes
    processes = []
    for _ in range(num_workers):
        p = mp.Process(target=worker,
                       args=(filepaths, msg_queue, task_index, task_lock))
        p.start()
        processes.append(p)

    # Process received messages until all the tasks are completed
    num_terminated_processes = 0
    pcap_counter = 0
    new_network_keys = 0
    new_link_keys = 0
    while num_terminated_processes < num_workers:
        msg_type, msg_obj = msg_queue.get()
        if msg_type is config.RETURN_MSG:
            num_terminated_processes += 1
            logging.debug(
                "The process with ID {} has no more pcap files to parse"
                "".format(msg_obj))
        elif msg_type is config.DEBUG_MSG:
            logging.debug(msg_obj)
        elif msg_type is config.INFO_MSG:
            logging.info(msg_obj)
        elif msg_type is config.WARNING_MSG:
            logging.warning(msg_obj)
        elif msg_type is config.ERROR_MSG:
            logging.error(msg_obj)
        elif msg_type is config.CRITICAL_MSG:
            logging.critical(msg_obj)
        elif msg_type is config.PCAP_MSG:
            pcap_counter += 1
            logging.info("Parsed {} out of the {} pcap files"
                         "".format(pcap_counter, len(filepaths)))
        elif msg_type is config.PKT_MSG:
            config.db.insert_pkt(msg_obj)
        elif msg_type is config.NETWORK_KEYS_MSG:
            for key_name in msg_obj.keys():
                if key_name not in config.network_keys.keys():
                    if msg_obj[key_name] not in config.network_keys.values():
                        config.network_keys[key_name] = msg_obj[key_name]
                        new_network_keys += 1
        elif msg_type is config.LINK_KEYS_MSG:
            for key_name in msg_obj.keys():
                if key_name not in config.link_keys.keys():
                    if msg_obj[key_name] not in config.link_keys.values():
                        config.link_keys[key_name] = msg_obj[key_name]
                        new_link_keys += 1
        elif msg_type is config.NETWORKS_MSG:
            for epid in msg_obj.keys():
                if epid not in config.networks.keys():
                    config.networks[epid] = msg_obj[epid]
                else:
                    config.networks[epid].update(msg_obj[epid])
        elif msg_type is config.DEVICES_MSG:
            for extendedaddr in msg_obj.keys():
                config.update_devices(
                    extendedaddr,
                    msg_obj[extendedaddr]["macdevtype"],
                    msg_obj[extendedaddr]["nwkdevtype"])
        elif msg_type is config.ADDRESSES_MSG:
            for (shortaddr, panid) in msg_obj.keys():
                if (shortaddr, panid) not in config.addresses.keys():
                    config.addresses[(shortaddr, panid)] = (
                        msg_obj[(shortaddr, panid)]
                    )
                elif (config.addresses[(shortaddr, panid)]
                      != msg_obj[(shortaddr, panid)]):
                    config.addresses[(shortaddr, panid)] = "Conflicting Data"
        elif msg_type is config.PAIRS_MSG:
            for (srcaddr, dstaddr, panid) in msg_obj.keys():
                config.update_pairs(
                    srcaddr,
                    dstaddr,
                    panid,
                    msg_obj[(srcaddr, dstaddr, panid)]["first"])
                config.update_pairs(
                    srcaddr,
                    dstaddr,
                    panid,
                    msg_obj[(srcaddr, dstaddr, panid)]["last"])
        else:
            raise ValueError("Unknown message type \"{}\"".format(msg_type))

    # Make sure that all processes terminated
    for p in processes:
        p.join()
    logging.info("All {} workers completed their tasks"
                 "".format(num_workers))

    # Make sure that the message queue is empty
    if not msg_queue.empty():
        raise ValueError("Expected the message queue to be empty")

    # Commit the received data to the database
    config.db.commit()

    # Log a summary of sniffed keys and derived information
    logging.info("Sniffed {} previously unknown network keys"
                 "".format(new_network_keys))
    logging.info("Sniffed {} previously unknown link keys"
                 "".format(new_link_keys))
    logging.info("Discovered the EPID of {} networks"
                 "".format(len(config.networks)))
    logging.info("Discovered the extended address of {} devices"
                 "".format(len(config.devices)))
    logging.info("Discovered the short-to-extended address mapping of "
                 "{} devices".format(len(config.addresses)))
    logging.info("Discovered {} flows of MAC Data packets"
                 "".format(len(config.pairs)))

    # Store the derived information into the database
    config.db.store_networks(config.networks)
    config.db.store_devices(config.devices)
    config.db.store_addresses(config.addresses)
    config.db.store_pairs(config.pairs)
    config.db.commit()

    # Update the packets table using the derived information
    logging.info("Updating the database...")
    config.db.update_packets()
    config.db.commit()
    logging.info("Finished updating the database")

    # Log a summary of the generated warnings
    warnings = config.db.fetch_values(["warning_msg"], None, True)
    warnings.sort(key=config.custom_sorter)
    for warning in warnings:
        message = warning[0]
        if message is None:
            continue
        frequency = config.db.matching_frequency([("warning_msg", message)])
        logging.warning("Generated {} \"{}\" parsing warnings"
                        "".format(frequency, message))

    # Log a summary of the generated errors
    errors = config.db.fetch_values(["error_msg"], None, True)
    errors.sort(key=config.custom_sorter)
    for error in errors:
        message = error[0]
        if message is None:
            continue
        frequency = config.db.matching_frequency([("error_msg", message)])
        logging.warning("Generated {} \"{}\" parsing errors"
                        "".format(frequency, message))

    # Disconnection from the database
    config.db.disconnect()
