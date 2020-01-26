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

import os
import string
import sqlite3

from scapy.all import *


# Make sure that the configuration directory exists
config_dir = os.path.join(os.path.expanduser("~"), ".config", "zigator")
os.makedirs(config_dir, exist_ok=True)

# Configure Scapy to assume that Zigbee is above the MAC layer
conf.dot15d4_protocol = "zigbee"

# Define the columns of the table in the database
columns = [
        ("pcap_directory", "TEXT", "NOT NULL"),
        ("pcap_filename", "TEXT", "NOT NULL"),
        ("pkt_num", "INTEGER", "NOT NULL")
]

# Define sets for sanity checks of the column definitions
allowed_characters = set(string.ascii_letters + string.digits + "_")
allowed_types = set(["TEXT", "INTEGER", "REAL", "BLOB"])
allowed_constraints = set([None, "NOT NULL"])

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
    first_column = True
    for column in columns:
        if not first_column:
            table_creation_command += ", "

        for c in column[0]:
            if c not in allowed_characters:
                raise ValueError("The character \"{}\" in the name of the "
                                 "column \"{}\" is not allowed"
                                 "".format(c, column[0]))
        table_creation_command += column[0]

        if column[1] not in allowed_types:
            raise ValueError("The column type \"{}\" is not in the "
                             "set of allowed column types {}"
                             "".format(column[1], allowed_types))
        table_creation_command += " " + column[1]

        if column[2] not in allowed_constraints:
            raise ValueError("The column constraint \"{}\" is not in the "
                             "set of allowed column constraints {}"
                             "".format(column[2], allowed_constraints))
        if column[2] is not None:
            table_creation_command += " " + column[2]
        first_column = False
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
