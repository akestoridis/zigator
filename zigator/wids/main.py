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
import os
import threading
import zipfile
from collections import deque
from glob import glob
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
PCAP_PERIOD = 0.0
NUM_ZIP_FILES = 0
LINK_KEY_NAMES = []
ANS = None
PKT_DEQUE = deque()


def check_zip_files():
    if NUM_ZIP_FILES > 0:
        filepaths = glob(
            os.path.join(OUTPUT_DIRECTORY, "*.{}.pcap.zip".format(SENSOR_ID)),
        )
        zip_files = [os.path.basename(filepath) for filepath in filepaths]
        excess_zip_files = len(zip_files) + 1 - NUM_ZIP_FILES
        if excess_zip_files > 0:
            zip_files.sort()
            for i in range(excess_zip_files):
                os.remove(os.path.join(OUTPUT_DIRECTORY, zip_files[i]))


def archive_file(pcap_filename):
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
            logging.info("Archived the \"{}\" file".format(pcap_filename))
    except Exception:
        logging.error(
            "An exception was raised while trying to archive the "
            + "\"{}\" file".format(pcap_filename),
        )


def detect_events():
    detection.panid_conflict(PANID, EPID)
    detection.unsecured_rejoinreq(PANID)
    detection.key_leakage(PANID, LINK_KEY_NAMES)
    detection.low_battery(PANID)


def collect_data():
    collection.basic_information()
    collection.battery_percentage()


def packet_handler(pkt):
    tmp_time = pkt.time
    pkt = Dot15d4FCS(bytes(pkt))
    pkt.time = tmp_time
    PKT_DEQUE.append(pkt)


def worker(db_filepath, max_uncommitted_entries, batch_delay):
    start_time = 0.0
    pkt_num = 0
    num_uncommitted_entries = 0
    config.db.connect(db_filepath)
    while True:
        if len(PKT_DEQUE) > 0:
            pkt = PKT_DEQUE.popleft()
            if pkt is None:
                if num_uncommitted_entries > 0:
                    config.db.commit()
                config.db.disconnect()
                break

            if float(pkt.time) - start_time > PCAP_PERIOD:
                archive_thread = threading.Thread(
                    target=archive_file,
                    args=("{:.6f}.{}.pcap".format(start_time, SENSOR_ID),),
                )
                archive_thread.start()
                start_time = float(pkt.time)
                pkt_num = 0

            pcap_filepath = os.path.join(
                OUTPUT_DIRECTORY,
                "{:.6f}.{}.pcap".format(start_time, SENSOR_ID),
            )
            wrpcap(pcap_filepath, pkt, append=True)

            pkt_num += 1
            config.reset_entries()
            head, tail = os.path.split(os.path.abspath(pcap_filepath))
            config.entry["pcap_directory"] = head
            config.entry["pcap_filename"] = tail
            config.entry["pkt_num"] = pkt_num
            config.entry["pkt_time"] = float(pkt.time)
            phy_fields(pkt, None)
            if config.entry["error_msg"] is None:
                derive_info()

            collect_data()
            detect_events()
            if num_uncommitted_entries >= max_uncommitted_entries:
                config.db.commit()
                num_uncommitted_entries = 0
            else:
                num_uncommitted_entries += 1
        else:
            if num_uncommitted_entries > 0:
                config.db.commit()
                num_uncommitted_entries = 0
            if batch_delay > 0.0:
                sleep(batch_delay)


def main(
    sensor_id,
    panid,
    epid,
    db_filepath,
    output_directory,
    ifname,
    pcap_period,
    num_zip_files,
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
    global PCAP_PERIOD
    global NUM_ZIP_FILES
    global LINK_KEY_NAMES
    global ANS

    try:
        # Indicate that the worker thread has not started yet
        worker_thread = None

        # Update some of the global variables
        SENSOR_ID = sensor_id
        PANID = "0x{:04x}".format(int(panid, 16))
        EPID = format(int(epid, 16), "016x")
        OUTPUT_DIRECTORY = output_directory
        PCAP_PERIOD = pcap_period
        NUM_ZIP_FILES = num_zip_files
        LINK_KEY_NAMES = link_key_names

        # Log the configuration for the WIDS sensor operation
        logging.info("Sensor ID: {}".format(SENSOR_ID))
        logging.info("PAN ID: {}".format(PANID))
        logging.info("Extended PAN ID: {}".format(EPID))
        logging.info("Database filepath: {}".format(db_filepath))
        logging.info("Output directory: {}".format(OUTPUT_DIRECTORY))
        logging.info("Interface name: {}".format(ifname))
        logging.info("Maximum pcap file duration: {} s".format(PCAP_PERIOD))
        logging.info("Maximum number of zip files: {}".format(NUM_ZIP_FILES))
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
        ANS = input("Do you want to start the WIDS sensor operation? [y/N] ")
        if ANS != "y":
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

        # Start a web server if the required parameters were provided
        if ipaddr is not None and portnum is not None:
            server.start(
                sensor_id,
                output_directory,
                db_filepath,
                ipaddr,
                portnum,
            )

        # Start the worker thread
        worker_thread = threading.Thread(
            target=worker,
            args=(db_filepath, max_uncommitted_entries, batch_delay),
        )
        worker_thread.start()

        # Process captured packets until the interrupt key is hit
        logging.info(
            "Operating as a WIDS sensor until the interrupt key (Ctrl-C) is "
            + "hit...",
        )
        sniff(count=0, store=False, prn=packet_handler, iface=ifname)
        logging.info("Stopped operating as a WIDS sensor")
    finally:
        # Check whether clean-up actions should be executed
        if ANS == "y":
            # Stop the web server if it had started
            if ipaddr is not None and portnum is not None:
                server.stop()

            # Stop the worker thread if it had started
            if worker_thread is not None:
                logging.info("Stopping the worker thread...")
                PKT_DEQUE.append(None)
                worker_thread.join()
                logging.info("Stopped the worker thread")
