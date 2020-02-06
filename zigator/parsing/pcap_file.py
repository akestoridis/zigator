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

import binascii
import logging
import os

from scapy.all import PcapReader

from .. import config
from .phy_fields import phy_fields


def pcap_file(filepath):
    """Parse all packets in the provided pcap file."""
    # Reset all data entries in the shared dictionary
    config.reset_entries()

    # Collect data that are common for all the packets of the pcap file
    head, tail = os.path.split(os.path.abspath(filepath))
    config.entry["pcap_directory"] = head
    config.entry["pcap_filename"] = tail

    # Parse the packets of the pcap file
    config.entry["pkt_num"] = 0
    logging.info("Reading packets from \"{}\"".format(filepath))
    for pkt in PcapReader(filepath):
        # Collect some data about the packet
        config.entry["pkt_num"] += 1
        config.entry["raw_pkt"] = binascii.hexlify(raw(pkt))
        config.entry["show_pkt"] = pkt.show(dump=True)

        # Collect more data about the packet from the PHY layer and onward
        phy_fields(pkt)

        # Insert the collected data into the database
        config.insert_pkt_into_database()

        # Reset only the data entries that the next packet may change
        config.reset_entries(keep=["pcap_directory",
                                   "pcap_filename",
                                   "pkt_num"])
    logging.info("Parsed {} packets from \"{}\""
                 "".format(config.entry["pkt_num"], filepath))
