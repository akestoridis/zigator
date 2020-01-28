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

"""
Configuration script for the zigator package
"""

import logging
import os
import string
import sqlite3

from scapy.all import conf


# Configure the logging system
logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)

# Make sure that the configuration directory exists
config_dir = os.path.join(os.path.expanduser("~"), ".config", "zigator")
os.makedirs(config_dir, exist_ok=True)

# Configure Scapy to assume that Zigbee is above the MAC layer
conf.dot15d4_protocol = "zigbee"

# Define the columns of the table in the database
columns = [
    ("pcap_directory", "TEXT"),
    ("pcap_filename", "TEXT"),
    ("pkt_num", "INTEGER"),
    ("raw_pkt", "TEXT"),
    ("show_pkt", "TEXT"),
    ("phy_length", "INTEGER"),
    ("mac_fcs", "TEXT"),
    ("mac_frametype", "TEXT"),
    ("mac_security", "TEXT"),
    ("mac_framepending", "TEXT"),
    ("mac_ackreq", "TEXT"),
    ("mac_panidcomp", "TEXT"),
    ("mac_dstaddrmode", "TEXT"),
    ("mac_frameversion", "TEXT"),
    ("mac_srcaddrmode", "TEXT"),
    ("mac_seqnum", "INTEGER"),
    ("mac_dstpanid", "TEXT"),
    ("mac_dstshortaddr", "TEXT"),
    ("mac_dstextendedaddr", "TEXT"),
    ("mac_srcpanid", "TEXT"),
    ("mac_srcshortaddr", "TEXT"),
    ("mac_srcextendedaddr", "TEXT"),
    ("mac_cmd_id", "TEXT"),
    ("mac_assocreq_devtype", "TEXT"),
    ("mac_assocreq_powsrc", "TEXT"),
    ("mac_assocreq_rxidle", "TEXT"),
    ("mac_assocreq_seccap", "TEXT"),
    ("mac_assocreq_allocaddr", "TEXT"),
    ("mac_assocresp_shortaddr", "TEXT"),
    ("mac_assocresp_status", "TEXT"),
    ("mac_disassoc_reason", "TEXT"),
    ("mac_realign_panid", "TEXT"),
    ("mac_realign_coordaddr", "TEXT"),
    ("mac_realign_channel", "INTEGER"),
    ("mac_realign_shortaddr", "TEXT"),
    ("mac_gtsreq_length", "INTEGER"),
    ("mac_gtsreq_dir", "TEXT"),
    ("mac_gtsreq_chartype", "TEXT"),
    ("mac_beacon_beaconorder", "INTEGER"),
    ("mac_beacon_sforder", "INTEGER"),
    ("mac_beacon_finalcap", "INTEGER"),
    ("mac_beacon_ble", "INTEGER"),
    ("mac_beacon_pancoord", "INTEGER"),
    ("mac_beacon_assocpermit", "INTEGER"),
    ("mac_beacon_gtsnum", "INTEGER"),
    ("mac_beacon_gtspermit", "INTEGER"),
    ("mac_beacon_gtsmask", "INTEGER"),
    ("mac_beacon_nsap", "INTEGER"),
    ("mac_beacon_neap", "INTEGER"),
    ("nwk_beacon_protocolid", "INTEGER"),
    ("nwk_beacon_stackprofile", "INTEGER"),
    ("nwk_beacon_protocolversion", "TEXT"),
    ("nwk_beacon_routercap", "INTEGER"),
    ("nwk_beacon_devdepth", "INTEGER"),
    ("nwk_beacon_edcap", "INTEGER"),
    ("nwk_beacon_epid", "TEXT"),
    ("nwk_beacon_txoffset", "INTEGER"),
    ("nwk_beacon_updateid", "INTEGER"),
    ("warning_msg", "TEXT"),
    ("error_msg", "TEXT")
]

# Define sets that will be used to construct valid column definitions
allowed_characters = set(string.ascii_letters + string.digits + "_")
allowed_types = set(["TEXT", "INTEGER", "REAL", "BLOB"])
constrained_columns = set([
    "pcap_directory",
    "pcap_filename",
    "pkt_num",
    "raw_pkt",
    "show_pkt"
])

# Use a shared dictionary to set up data entries
entry = {column[0]: None for column in columns}

# Initialize global variables for interacting with the database
db_connection = None
db_cursor = None

# Define the filepath of the database
db_filepath = os.path.join(config_dir, "traffic.db")


def reset_entries(keep=[]):
    # Reset all data entries in the shared dictionary except
    # the ones that were requested to maintain their values
    if keep is None:
        keep = []
    for column_name in entry.keys():
        if column_name not in keep:
            entry[column_name] = None


def initialize_db():
    global db_connection
    global db_cursor

    # Open a connection with the database
    db_connection = sqlite3.connect(db_filepath)
    db_connection.text_factory = str
    db_cursor = db_connection.cursor()

    # TODO: Stop automatically resetting the table
    #       when its definition becomes stable
    db_cursor.execute("DROP TABLE IF EXISTS packets")
    db_connection.commit()

    # Create a table for the parsed packets, if it doesn't already exist
    table_creation_command = "CREATE TABLE IF NOT EXISTS packets("
    delimiter_needed = False
    for column in columns:
        if delimiter_needed:
            table_creation_command += ", "
        else:
            delimiter_needed = True

        column_name = column[0]
        column_type = column[1]

        for i in range(len(column_name)):
            if column_name[i] not in allowed_characters:
                raise ValueError("The character \"{}\" in the name of the "
                                 "column \"{}\" is not allowed"
                                 "".format(column_name[i], column_name))

        if column_name[0].isdigit():
            raise ValueError("The name of the column \"{}\" is not allowed "
                             "because it starts with a digit"
                             "".format(column_name))

        table_creation_command += column_name

        if column_type not in allowed_types:
            raise ValueError("The column type \"{}\" is not in the "
                             "set of allowed column types {}"
                             "".format(column_type, allowed_types))

        table_creation_command += " " + column_type

        if column_name in constrained_columns:
            table_creation_command += " NOT NULL"
    table_creation_command += ")"

    db_cursor.execute(table_creation_command)
    db_connection.commit()


def insert_pkt_into_database():
    global db_connection
    global db_cursor

    # Insert the parsed data into the database
    db_cursor.execute("INSERT INTO packets VALUES ({})".format(
                            ", ".join("?"*len(columns))),
                      tuple(entry[column[0]] for column in columns))
    db_connection.commit()


def finalize_db():
    global db_connection
    global db_cursor

    # Close the connection with the database
    db_connection.close()
    db_connection = None
    db_cursor = None
