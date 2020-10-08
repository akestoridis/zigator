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

from scapy.all import PcapReader

from .. import config
from .derive_info import derive_info
from .phy_fields import phy_fields


def pcap_file(filepath, msg_queue):
    """Parse all packets in the provided pcap file."""
    # Keep a copy of each dictionary that may change after parsing packets
    init_network_keys = config.network_keys.copy()
    init_link_keys = config.link_keys.copy()
    init_networks = config.networks.copy()
    init_devices = config.devices.copy()
    init_addresses = config.addresses.copy()
    init_pairs = config.pairs.copy()

    # Reset all data entries in the dictionary
    config.reset_entries()

    # Collect data that are common for all the packets of the pcap file
    head, tail = os.path.split(os.path.abspath(filepath))
    config.entry["pcap_directory"] = head
    config.entry["pcap_filename"] = tail

    # Parse the packets of the pcap file
    msg_queue.put(
        (config.INFO_MSG,
         "Reading packets from the \"{}\" file..."
         "".format(filepath)))
    config.entry["pkt_num"] = 0
    pcap_reader = PcapReader(filepath)
    for pkt in pcap_reader:
        # Collect some data about the packet
        config.entry["pkt_num"] += 1
        config.entry["pkt_time"] = float(pkt.time)
        config.entry["pkt_raw"] = bytes(pkt).hex()
        config.entry["pkt_show"] = pkt.show(dump=True)

        # Collect more data about the packet from the PHY layer and onward
        phy_fields(pkt, msg_queue)

        # Derive additional information from the parsed packet
        if config.entry["error_msg"] is None:
            derive_info()

        # Send a copy of the collected data to the main process
        msg_queue.put(
            (config.PKT_MSG,
             config.entry.copy()))

        # Reset only the data entries that the next packet may change
        config.reset_entries(keep=["pcap_directory",
                                   "pcap_filename",
                                   "pkt_num"])
    pcap_reader.close()

    # Log the number of parsed packets from this pcap file
    msg_queue.put(
        (config.INFO_MSG,
         "Parsed {} packets from the \"{}\" file"
         "".format(config.entry["pkt_num"], filepath)))

    # Send a copy of each dictionary that changed after parsing packets
    if config.network_keys != init_network_keys:
        msg_queue.put((config.NETWORK_KEYS_MSG, config.network_keys.copy()))
    if config.link_keys != init_link_keys:
        msg_queue.put((config.LINK_KEYS_MSG, config.link_keys.copy()))
    if config.networks != init_networks:
        msg_queue.put((config.NETWORKS_MSG, config.networks.copy()))
    if config.devices != init_devices:
        msg_queue.put((config.DEVICES_MSG, config.devices.copy()))
    if config.addresses != init_addresses:
        msg_queue.put((config.ADDRESSES_MSG, config.addresses.copy()))
    if config.pairs != init_pairs:
        msg_queue.put((config.PAIRS_MSG, config.pairs.copy()))
