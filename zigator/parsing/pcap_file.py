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

import copy
import os

from scapy.all import (
    CookedLinux,
    PcapReader,
)

from .. import config
from .derive_info import derive_info
from .phy_fields import phy_fields
from .sll_fields import sll_fields


def pcap_file(filepath, msg_queue):
    """Parse all packets in the provided pcap file."""
    # Keep a copy of each dictionary that may change after parsing packets
    init_network_keys = copy.deepcopy(config.network_keys)
    init_link_keys = copy.deepcopy(config.link_keys)
    init_networks = copy.deepcopy(config.networks)
    init_short_addresses = copy.deepcopy(config.short_addresses)
    init_extended_addresses = copy.deepcopy(config.extended_addresses)
    init_pairs = copy.deepcopy(config.pairs)

    # Reset all data entries in the dictionary
    config.reset_entries()

    # Collect data that are common for all the packets of the pcap file
    head, tail = os.path.split(os.path.abspath(filepath))
    config.entry["pcap_directory"] = head
    config.entry["pcap_filename"] = tail

    # Parse the packets of the pcap file
    msg_queue.put(
        (
            config.INFO_MSG,
            "Reading packets from the \"{}\" file...".format(filepath),
        ),
    )
    config.entry["pkt_num"] = 0
    pcap_reader = PcapReader(filepath)
    for pkt in pcap_reader:
        # Collect data about the packet
        config.entry["pkt_num"] += 1
        config.entry["pkt_time"] = float(pkt.time)
        if pkt.haslayer(CookedLinux):
            sll_fields(pkt, msg_queue)
        else:
            phy_fields(pkt, msg_queue)

        # Derive additional information from the parsed packet
        if config.entry["error_msg"] is None:
            derive_info()

        # Send a copy of the collected data to the main process
        msg_queue.put((config.PKT_MSG, copy.deepcopy(config.entry)))

        # Reset only the data entries that the next packet may change
        config.reset_entries(
            keep={"pcap_directory", "pcap_filename", "pkt_num"},
        )
    pcap_reader.close()

    # Log the number of parsed packets from this pcap file
    msg_queue.put(
        (
            config.INFO_MSG,
            "Parsed {} packets from the \"{}\" file".format(
                config.entry["pkt_num"],
                filepath,
            ),
        ),
    )

    # Send a copy of each dictionary that changed after parsing packets
    if config.network_keys != init_network_keys:
        msg_queue.put(
            (config.NETWORK_KEYS_MSG, copy.deepcopy(config.network_keys)),
        )
    if config.link_keys != init_link_keys:
        msg_queue.put((config.LINK_KEYS_MSG, copy.deepcopy(config.link_keys)))
    if config.networks != init_networks:
        msg_queue.put((config.NETWORKS_MSG, copy.deepcopy(config.networks)))
    if config.short_addresses != init_short_addresses:
        msg_queue.put(
            (
                config.SHORT_ADDRESSES_MSG,
                copy.deepcopy(config.short_addresses),
            ),
        )
    if config.extended_addresses != init_extended_addresses:
        msg_queue.put(
            (
                config.EXTENDED_ADDRESSES_MSG,
                copy.deepcopy(config.extended_addresses),
            ),
        )
    if config.pairs != init_pairs:
        msg_queue.put((config.PAIRS_MSG, copy.deepcopy(config.pairs)))
