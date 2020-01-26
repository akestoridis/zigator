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

import logging
import os

from scapy.all import *

from . import config


def pcap_file(filepath):
    """Parse all packets in the provided pcap file."""
    config.reset_entries()
    head, tail = os.path.split(os.path.abspath(filepath))
    config.entry["pcap_directory"] = head
    config.entry["pcap_filename"] = tail
    config.entry["pkt_num"] = 0
    logging.info("Reading packets from \"{}\"".format(filepath))
    for pkt in PcapReader(filepath):
        config.entry["pkt_num"] += 1
        config.insert_pkt_into_database()
        config.reset_entries(keep=["pcap_directory",
                                   "pcap_filename",
                                   "pkt_num"])
