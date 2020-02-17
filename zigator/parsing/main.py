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
import os

from .. import config
from .pcap_file import pcap_file


def main(pcap_dirpath, db_filepath):
    """Parse all pcap files in the provided directory."""
    # Sanity check
    if not os.path.isdir(pcap_dirpath):
        raise ValueError("The provided directory \"{}\" "
                         "does not exist".format(pcap_dirpath))

    # Initialize the database that will store the parsed data
    config.db.connect(db_filepath)
    config.db.create_table("packets")

    # Get a sorted list of pcap filepaths
    filepaths = glob.glob(os.path.join(pcap_dirpath, "*.[pP][cC][aA][pP]"))
    filepaths.sort()
    logging.info("Detected {} pcap files in the directory \"{}\""
                 "".format(len(filepaths), pcap_dirpath))

    # Parse the detected pcap files
    pcap_counter = 0
    for filepath in filepaths:
        pcap_file(filepath)
        pcap_counter += 1
        logging.info("Parsed {} out of the {} pcap files"
                     "".format(pcap_counter, len(filepaths)))

    # Log the derived information in detail for debugging purposes
    logging.debug("Networks: {}".format(config.networks))
    logging.debug("Devices: {}".format(config.devices))
    logging.debug("Addresses: {}".format(config.addresses))
    logging.debug("Pairs: {}".format(config.pairs))

    # Log a summary of the derived information
    logging.info("Discovered {} networks".format(len(config.networks)))
    logging.info("Discovered {} devices".format(len(config.devices)))
    logging.info("Discovered {} short-to-extended address mappings"
                 "".format(len(config.addresses)))
    logging.info("Discovered {} pairs of short addresses exchanging packets"
                 "".format(len(config.pairs)))

    # Log a summary of the generated warnings
    warnings = config.db.distinct_values(["warning_msg"], None)
    for warning in warnings:
        message = warning[0]
        if message is None:
            continue
        frequency = config.db.matching_frequency([("warning_msg", message)])
        logging.warning("Generated {} \"{}\" parsing warnings"
                        "".format(frequency, message))

    # Log a summary of the generated errors
    errors = config.db.distinct_values(["error_msg"], None)
    for error in errors:
        message = error[0]
        if message is None:
            continue
        frequency = config.db.matching_frequency([("error_msg", message)])
        logging.warning("Generated {} \"{}\" parsing errors"
                        "".format(frequency, message))

    # Disconnection from the database
    config.db.disconnect()
