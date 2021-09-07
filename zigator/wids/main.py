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

import glob
import logging
import os
import threading
import zipfile

from scapy.all import Dot15d4FCS
from scapy.all import sniff
from scapy.all import wrpcap

from . import collection
from . import detection
from . import server
from .. import config
from ..parsing.derive_info import derive_info
from ..parsing.phy_fields import phy_fields

SENSOR_ID = None
PANID = None
EPID = None
OUTPUT_DIRECTORY = None
PCAP_PERIOD = 0.0
START_TIME = 0.0
NUM_ZIP_FILES = 0
LINK_KEY_NAMES = []
PKT_NUM = 0
ANS = None


def check_zip_files():
    if NUM_ZIP_FILES > 0:
        zip_files = [
            os.path.basename(filepath) for filepath in glob.glob(os.path.join(
                OUTPUT_DIRECTORY,
                "*.{}.pcap.zip".format(SENSOR_ID)))
        ]
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
            with zipfile.ZipFile(pcap_filepath + ".zip", mode="w",
                                 compression=zipfile.ZIP_DEFLATED) as zf:
                zf.write(pcap_filepath, arcname=pcap_filename)
            os.remove(pcap_filepath)
            logging.info("Archived the \"{}\" file".format(pcap_filename))
    except Exception:
        logging.error("An exception was raised while trying to archive "
                      "the \"{}\" file".format(pcap_filename))


def detect_events():
    detection.panid_conflict(PANID, EPID)
    detection.unsecured_rejoinreq(PANID)
    detection.key_leakage(PANID, LINK_KEY_NAMES)
    detection.low_battery(PANID)


def collect_data():
    collection.basic_information()
    collection.battery_percentage()


def packet_handler(pkt):
    global START_TIME
    global PKT_NUM

    tmp_time = pkt.time
    pkt = Dot15d4FCS(bytes(pkt))
    pkt.time = tmp_time

    if float(pkt.time) - START_TIME > PCAP_PERIOD:
        archive_thread = threading.Thread(
            target=archive_file,
            args=("{:.6f}.{}.pcap".format(START_TIME, SENSOR_ID),))
        archive_thread.start()
        START_TIME = float(pkt.time)
        PKT_NUM = 0

    pcap_filepath = os.path.join(
        OUTPUT_DIRECTORY, "{:.6f}.{}.pcap".format(START_TIME, SENSOR_ID))
    wrpcap(pcap_filepath, pkt, append=True)

    PKT_NUM += 1
    config.reset_entries()
    head, tail = os.path.split(os.path.abspath(pcap_filepath))
    config.entry["pcap_directory"] = head
    config.entry["pcap_filename"] = tail
    config.entry["pkt_num"] = PKT_NUM
    config.entry["pkt_time"] = float(pkt.time)
    phy_fields(pkt, None)
    if config.entry["error_msg"] is None:
        derive_info()

    collect_data()
    detect_events()
    config.db.commit()


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

        # Start a web server if the required parameters were provided
        if ipaddr is not None and portnum is not None:
            server.start(
                sensor_id,
                output_directory,
                db_filepath,
                ipaddr,
                portnum)

        # Process captured packets until the interrupt key is hit
        logging.info("Operating as a WIDS sensor until "
                     "the interrupt key (Ctrl-C) is hit...")
        sniff(count=0, store=False, prn=packet_handler, iface=ifname)
        logging.info("Stopped operating as a WIDS sensor")
    finally:
        # Check whether clean-up actions should be executed
        if ANS == "y":
            # Stop the web server if it had started
            if ipaddr is not None and portnum is not None:
                server.stop()

            # Disconnection from the database
            config.db.disconnect()
