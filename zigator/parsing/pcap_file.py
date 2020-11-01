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

from scapy.all import CookedLinux
from scapy.all import Dot15d4FCS
from scapy.all import PcapReader

from .. import config
from .derive_info import derive_info
from .phy_fields import phy_fields


def get_sll_pkttype(pkt):
    sll_pkttypes = {
        0: "The packet was sent to us by another host",
        1: "The packet was broadcasted by another host",
        2: "The packet was multicasted by another host",
        3: "The packet was sent to another host by another host",
        4: "The packet was sent by us"
    }
    pkttype_id = pkt[CookedLinux].pkttype
    return sll_pkttypes.get(pkttype_id, "Unknown SLL packet type")


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

        # Check whether the packet has an SLL header or not
        if pkt.haslayer(CookedLinux):
            # Collect data from the SLL header
            config.entry["sll_pkttype"] = get_sll_pkttype(pkt)
            config.entry["sll_arphrdtype"] = pkt[CookedLinux].lladdrtype
            config.entry["sll_addrlength"] = pkt[CookedLinux].lladdrlen
            config.entry["sll_addr"] = pkt[CookedLinux].src.hex()
            config.entry["sll_protocoltype"] = pkt[CookedLinux].proto

            # Collect more data about the packet
            if config.entry["sll_protocoltype"] != 0x00f6:
                config.entry["error_msg"] = "PE001: Unsupported protocol type"
            elif config.entry["sll_arphrdtype"] != 0x0325:
                config.entry["error_msg"] = "PE002: Unsupported ARPHRD type"
            else:
                phy_fields(Dot15d4FCS(bytes(pkt[CookedLinux].payload)),
                           msg_queue)
        else:
            # Collect more data about the packet
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
