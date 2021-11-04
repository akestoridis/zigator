# Copyright (C) 2021 Dimitrios-Georgios Akestoridis
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
import signal
import threading
import zipfile
from collections import deque
from copy import deepcopy
from glob import glob
from queue import Empty
from time import sleep

from scapy.all import (
    Dot15d4FCS,
    sniff,
    wrpcap,
)

from . import (
    collection,
    detection,
    server,
)
from .. import config
from ..parsing.derive_info import derive_info
from ..parsing.phy_fields import phy_fields

SENSOR_ID = None
PANID = None
EPID = None
OUTPUT_DIRECTORY = None
MAX_PCAP_DURATION = 0.0
MAX_ZIP_FILES = 0
LINK_KEY_NAMES = []
HELPER_DEQUE = deque()
START_TIME = 0.0
PKT_NUM = 0


def main(
    sensor_id,
    panid,
    epid,
    db_filepath,
    output_directory,
    ifname,
    max_pcap_duration,
    max_zip_files,
    link_key_names,
    max_uncommitted_entries,
    batch_delay,
    table_thres,
    table_reduct,
    ipaddr,
    portnum,
):
    """Operate as a WIDS sensor."""
    global SENSOR_ID
    global PANID
    global EPID
    global OUTPUT_DIRECTORY
    global MAX_PCAP_DURATION
    global MAX_ZIP_FILES
    global LINK_KEY_NAMES

    try:
        # Initialize the local variables
        helper_thread = None
        answer = None

        # Update some of the global variables
        SENSOR_ID = sensor_id
        PANID = "0x{:04x}".format(int(panid, 16))
        EPID = format(int(epid, 16), "016x")
        OUTPUT_DIRECTORY = output_directory
        MAX_PCAP_DURATION = max_pcap_duration
        MAX_ZIP_FILES = max_zip_files
        LINK_KEY_NAMES = link_key_names

        # Log the configuration for the WIDS sensor operation
        logging.info("Sensor ID: {}".format(SENSOR_ID))
        logging.info("PAN ID: {}".format(PANID))
        logging.info("Extended PAN ID: {}".format(EPID))
        logging.info("Database filepath: {}".format(db_filepath))
        logging.info("Output directory: {}".format(OUTPUT_DIRECTORY))
        logging.info("Interface name: {}".format(ifname))
        logging.info(
            "Maximum pcap file duration: {} s".format(MAX_PCAP_DURATION),
        )
        logging.info("Maximum number of zip files: {}".format(MAX_ZIP_FILES))
        logging.info("Link key names: {}".format(LINK_KEY_NAMES))
        logging.info(
            "Maximum number of uncommitted entries: "
            + "{}".format(max_uncommitted_entries),
        )
        logging.info("Batch delay: {} s".format(batch_delay))
        logging.info("Table threshold: {} rows".format(table_thres))
        logging.info("Table reduction: {} rows".format(table_reduct))
        logging.info("IP address: {}".format(ipaddr))
        logging.info("Port number: {}".format(portnum))

        # Print a notice
        print("############################################################")
        print("#                          NOTICE                          #")
        print("#                                                          #")
        print("# Before starting the WIDS sensor operation, make sure     #")
        print("# that the transceiver is enabled and properly configured  #")
        print("# (e.g., it should already be tuned to the appropriate     #")
        print("# channel).                                                #")
        print("############################################################")
        answer = input(
            "Do you want to start the WIDS sensor operation? [y/N] ",
        )
        if answer != "y":
            logging.info("Canceling the WIDS sensor operation...")
            return

        # Make sure that the output directory exists
        os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)

        # Initialize the database that will store data and events
        config.db.connect(db_filepath)
        config.db.create_table("basic_information")
        config.db.create_table("battery_percentages")
        config.db.create_table("events")
        config.db.create_count_trigger(
            "basic_information",
            table_thres,
            table_reduct,
        )
        config.db.create_count_trigger(
            "battery_percentages",
            table_thres,
            table_reduct,
        )
        config.db.create_count_trigger(
            "events",
            table_thres,
            table_reduct,
        )
        config.db.commit()
        config.db.disconnect()

        # Start the helper thread
        helper_thread = threading.Thread(
            target=helper,
            args=(
                sensor_id,
                db_filepath,
                output_directory,
                max_uncommitted_entries,
                batch_delay,
                ipaddr,
                portnum,
            ),
        )
        helper_thread.start()

        # Process captured packets until the interrupt key is hit
        logging.info(
            "Operating as a WIDS sensor until the interrupt key (Ctrl-C) is "
            + "hit...",
        )
        sniff(count=0, store=False, prn=packet_handler, iface=ifname)
        logging.info("Stopped operating as a WIDS sensor")
    finally:
        # Check whether clean-up actions should be executed
        if answer == "y" and helper_thread is not None:
            logging.info("Stopping the helper thread...")
            HELPER_DEQUE.append((config.RETURN_MSG, None))
            helper_thread.join()
            logging.info("Stopped the helper thread")


def packet_handler(pkt):
    global START_TIME
    global PKT_NUM

    tmp_time = pkt.time
    pkt = Dot15d4FCS(bytes(pkt))
    pkt.time = tmp_time

    if float(pkt.time) - START_TIME > MAX_PCAP_DURATION:
        HELPER_DEQUE.append(
            (config.PCAP_MSG, "{:.6f}.{}.pcap".format(START_TIME, SENSOR_ID)),
        )
        START_TIME = float(pkt.time)
        PKT_NUM = 0

    PKT_NUM += 1
    HELPER_DEQUE.append(
        (
            config.PKT_MSG,
            (
                pkt,
                os.path.join(
                    OUTPUT_DIRECTORY,
                    "{:.6f}.{}.pcap".format(START_TIME, SENSOR_ID),
                ),
                PKT_NUM,
            ),
        ),
    )


def helper(
    sensor_id,
    db_filepath,
    output_directory,
    max_uncommitted_entries,
    batch_delay,
    ipaddr,
    portnum,
):
    writing_queue = mp.Queue()
    preparsing_queue = mp.Queue()
    postparsing_queue = mp.Queue()

    writing_process = mp.Process(target=writer, args=(writing_queue,))
    parsing_process = mp.Process(
        target=parser,
        args=(preparsing_queue, postparsing_queue),
    )
    gathering_process = mp.Process(
        target=gatherer,
        args=(
            sensor_id,
            db_filepath,
            output_directory,
            max_uncommitted_entries,
            batch_delay,
            ipaddr,
            portnum,
            preparsing_queue,
            postparsing_queue,
        ),
    )

    writing_process.start()
    parsing_process.start()
    gathering_process.start()

    while True:
        if len(HELPER_DEQUE) > 0:
            msg_type, msg_obj = HELPER_DEQUE.popleft()
            if msg_type == config.PKT_MSG:
                writing_queue.put((msg_type, msg_obj))
                preparsing_queue.put((msg_type, msg_obj))
            elif msg_type == config.PCAP_MSG:
                writing_queue.put((msg_type, msg_obj))
            elif msg_type == config.RETURN_MSG:
                writing_queue.put((msg_type, msg_obj))
                preparsing_queue.put((msg_type, msg_obj))
                break
            else:
                logging.warning(
                    "Ignored unexpected message type \"{}\"".format(msg_type),
                )
        elif batch_delay > 0.0:
            sleep(batch_delay)

    logging.info("Waiting for the writing process to terminate...")
    writing_process.join()

    logging.info("Waiting for the parsing process to terminate...")
    parsing_process.join()

    logging.info("Waiting for the gathering process to terminate...")
    gathering_process.join()

    if not writing_queue.empty():
        raise ValueError("Expected the writing queue to be empty")

    if not preparsing_queue.empty():
        raise ValueError("Expected the preparsing queue to be empty")

    if not postparsing_queue.empty():
        raise ValueError("Expected the postparsing queue to be empty")


def writer(writing_queue):
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    while True:
        msg_type, msg_obj = writing_queue.get()
        if msg_type == config.PKT_MSG:
            wrpcap(msg_obj[1], msg_obj[0], append=True)
        elif msg_type == config.PCAP_MSG:
            compress_file(msg_obj)
        elif msg_type == config.RETURN_MSG:
            break
        else:
            logging.warning(
                "Ignored unexpected message type \"{}\"".format(msg_type),
            )


def compress_file(pcap_filename):
    try:
        check_zip_files()
        pcap_filepath = os.path.join(OUTPUT_DIRECTORY, pcap_filename)
        if os.path.isfile(pcap_filepath):
            with zipfile.ZipFile(
                pcap_filepath + ".zip",
                mode="w",
                compression=zipfile.ZIP_DEFLATED,
            ) as zf:
                zf.write(pcap_filepath, arcname=pcap_filename)
            os.remove(pcap_filepath)
            logging.info("Compressed the \"{}\" file".format(pcap_filename))
    except Exception:
        logging.error(
            "An exception was raised while trying to compress the "
            + "\"{}\" file".format(pcap_filename),
        )


def check_zip_files():
    if MAX_ZIP_FILES > 0:
        filepaths = glob(
            os.path.join(OUTPUT_DIRECTORY, "*.{}.pcap.zip".format(SENSOR_ID)),
        )
        zip_files = [os.path.basename(filepath) for filepath in filepaths]
        excess_zip_files = len(zip_files) + 1 - MAX_ZIP_FILES
        if excess_zip_files > 0:
            zip_files.sort()
            for i in range(excess_zip_files):
                os.remove(os.path.join(OUTPUT_DIRECTORY, zip_files[i]))


def parser(preparsing_queue, postparsing_queue):
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    prev_network_keys = deepcopy(config.network_keys)
    prev_link_keys = deepcopy(config.link_keys)
    prev_networks = deepcopy(config.networks)
    prev_short_addresses = deepcopy(config.short_addresses)
    prev_extended_addresses = deepcopy(config.extended_addresses)
    prev_pairs = deepcopy(config.pairs)

    while True:
        msg_type, msg_obj = preparsing_queue.get()
        if msg_type == config.PKT_MSG:
            pkt, pcap_filepath, pkt_num = msg_obj

            config.reset_entries()
            head, tail = os.path.split(os.path.abspath(pcap_filepath))
            config.entry["pcap_directory"] = head
            config.entry["pcap_filename"] = tail
            config.entry["pkt_num"] = pkt_num
            config.entry["pkt_time"] = float(pkt.time)
            phy_fields(pkt, None)
            if config.entry["error_msg"] is None:
                derive_info()

            postparsing_queue.put((config.PKT_MSG, deepcopy(config.entry)))
            if config.network_keys != prev_network_keys:
                new_network_keys = {}
                for key_name in config.network_keys.keys():
                    if key_name not in prev_network_keys.keys():
                        key_bytes = config.network_keys[key_name]
                        prev_network_keys[key_name] = key_bytes
                        new_network_keys[key_name] = key_bytes
                if len(new_network_keys.keys()) > 0:
                    postparsing_queue.put(
                        (config.NETWORK_KEYS_MSG, deepcopy(new_network_keys)),
                    )
            if config.link_keys != prev_link_keys:
                new_link_keys = {}
                for key_name in config.link_keys.keys():
                    if key_name not in prev_link_keys.keys():
                        key_bytes = config.link_keys[key_name]
                        prev_link_keys[key_name] = key_bytes
                        new_link_keys[key_name] = key_bytes
                if len(new_link_keys.keys()) > 0:
                    postparsing_queue.put(
                        (config.LINK_KEYS_MSG, deepcopy(new_link_keys)),
                    )
            if config.networks != prev_networks:
                prev_networks = deepcopy(config.networks)
                postparsing_queue.put(
                    (config.NETWORKS_MSG, deepcopy(prev_networks)),
                )
            if config.short_addresses != prev_short_addresses:
                prev_short_addresses = deepcopy(config.short_addresses)
                postparsing_queue.put(
                    (
                        config.SHORT_ADDRESSES_MSG,
                        deepcopy(prev_short_addresses),
                    ),
                )
            if config.extended_addresses != prev_extended_addresses:
                prev_extended_addresses = deepcopy(config.extended_addresses)
                postparsing_queue.put(
                    (
                        config.EXTENDED_ADDRESSES_MSG,
                        deepcopy(prev_extended_addresses),
                    ),
                )
            if config.pairs != prev_pairs:
                prev_pairs = deepcopy(config.pairs)
                postparsing_queue.put(
                    (config.PAIRS_MSG, deepcopy(prev_pairs)),
                )
        elif msg_type == config.NETWORK_KEYS_MSG:
            for key_name in msg_obj.keys():
                return_msg = config.add_new_key(
                    msg_obj[key_name],
                    "network",
                    key_name,
                )
                if return_msg is not None:
                    logging.warning(return_msg)
            prev_network_keys = deepcopy(config.network_keys)
        elif msg_type == config.LINK_KEYS_MSG:
            for key_name in msg_obj.keys():
                return_msg = config.add_new_key(
                    msg_obj[key_name],
                    "link",
                    key_name,
                )
                if return_msg is not None:
                    logging.warning(return_msg)
            prev_link_keys = deepcopy(config.link_keys)
        elif msg_type == config.RETURN_MSG:
            postparsing_queue.put((msg_type, msg_obj))
            break
        else:
            logging.warning(
                "Ignored unexpected message type \"{}\"".format(msg_type),
            )


def gatherer(
    sensor_id,
    db_filepath,
    output_directory,
    max_uncommitted_entries,
    batch_delay,
    ipaddr,
    portnum,
    preparsing_queue,
    postparsing_queue,
):
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    network_keys_lock = threading.Lock()
    link_keys_lock = threading.Lock()
    networks_lock = threading.Lock()
    short_addresses_lock = threading.Lock()
    extended_addresses_lock = threading.Lock()
    pairs_lock = threading.Lock()

    if ipaddr is not None and portnum is not None:
        server.start(
            sensor_id,
            output_directory,
            db_filepath,
            ipaddr,
            portnum,
            network_keys_lock,
            link_keys_lock,
            networks_lock,
            short_addresses_lock,
            extended_addresses_lock,
            pairs_lock,
            preparsing_queue,
        )

    num_uncommitted_entries = 0
    config.db.connect(db_filepath)
    while True:
        try:
            msg_type, msg_obj = postparsing_queue.get(timeout=batch_delay)
            if msg_type == config.PKT_MSG:
                config.entry = msg_obj
                collect_data()
                detect_events(link_keys_lock)
                if num_uncommitted_entries >= max_uncommitted_entries:
                    config.db.commit()
                    num_uncommitted_entries = 0
                else:
                    num_uncommitted_entries += 1
            elif msg_type == config.NETWORK_KEYS_MSG:
                with network_keys_lock:
                    for key_name in msg_obj.keys():
                        return_msg = config.add_new_key(
                            msg_obj[key_name],
                            "network",
                            key_name,
                        )
                        if return_msg is not None:
                            logging.warning(return_msg)
            elif msg_type == config.LINK_KEYS_MSG:
                with link_keys_lock:
                    for key_name in msg_obj.keys():
                        return_msg = config.add_new_key(
                            msg_obj[key_name],
                            "link",
                            key_name,
                        )
                        if return_msg is not None:
                            logging.warning(return_msg)
            elif msg_type == config.NETWORKS_MSG:
                with networks_lock:
                    config.networks = msg_obj
            elif msg_type == config.SHORT_ADDRESSES_MSG:
                with short_addresses_lock:
                    config.short_addresses = msg_obj
            elif msg_type == config.EXTENDED_ADDRESSES_MSG:
                with extended_addresses_lock:
                    config.extended_addresses = msg_obj
            elif msg_type == config.PAIRS_MSG:
                with pairs_lock:
                    config.pairs = msg_obj
            elif msg_type == config.RETURN_MSG:
                if num_uncommitted_entries > 0:
                    config.db.commit()
                    num_uncommitted_entries = 0
                config.db.disconnect()
                break
            else:
                logging.warning(
                    "Ignored unexpected message type \"{}\"".format(msg_type),
                )
        except Empty:
            if num_uncommitted_entries > 0:
                config.db.commit()
                num_uncommitted_entries = 0

    if ipaddr is not None and portnum is not None:
        server.stop()


def collect_data():
    collection.basic_information()
    collection.battery_percentage()


def detect_events(link_keys_lock):
    detection.panid_conflict(PANID, EPID)
    detection.unsecured_rejoinreq(PANID)
    detection.key_leakage(PANID, LINK_KEY_NAMES, link_keys_lock)
    detection.low_battery(PANID)
