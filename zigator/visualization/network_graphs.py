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

import os

import graphviz

from .. import config


def network_graphs(out_dirpath):
    """Generate a network graph for each pcap file."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Get the path of each pcap file
    pcap_filepaths = config.db.fetch_values(
        "packets",
        [
            "pcap_directory",
            "pcap_filename",
        ],
        None,
        True,
    )

    for pcap_filepath in pcap_filepaths:
        # Determine the subset of packets that will be examined
        conditions = [
            ("pcap_directory", pcap_filepath[0]),
            ("pcap_filename", pcap_filepath[1]),
            ("mac_frametype", "0b001: MAC Data"),
            (
                "mac_panidcomp",
                "0b1: "
                + "The source PAN ID is the same as the destination PAN ID",
            ),
            ("!mac_dstshortaddr", "0xffff"),
            ("error_msg", None),
        ]

        # Get all destination PAN IDs that were observed in these packets
        panids = config.db.fetch_values(
            "packets",
            [
                "mac_dstpanid",
            ],
            conditions,
            True
        )

        for panid in panids:
            # Determine the name of the output file
            out_filename = (
                os.path.splitext(pcap_filepath[1])[0] + "-" + panid[0]
            )

            # Get the addresses of nodes that have exchanged MAC Data packets
            addr_pairs = config.db.fetch_values(
                "packets",
                [
                    "mac_srcshortaddr",
                    "mac_dstshortaddr",
                ],
                conditions + [("mac_dstpanid", panid[0])],
                True,
            )

            # Derive the set of unique addresses
            addr_nodes = set()
            for addr_pair in addr_pairs:
                addr_nodes.add(addr_pair[0])
                addr_nodes.add(addr_pair[1])

            # Render a directed graph from the observed address pairs
            digraph = graphviz.Digraph(
                name=out_filename,
                directory=out_dirpath,
                format="pdf",
                engine="dot",
            )
            for addr_node in addr_nodes:
                nwkdevtype = config.db.get_nwkdevtype(
                    panid[0],
                    addr_node,
                    None,
                )
                if nwkdevtype == "Zigbee Coordinator":
                    fillcolor = "#FF0000"
                elif nwkdevtype == "Zigbee Router":
                    fillcolor = "#FFA500"
                elif nwkdevtype == "Zigbee End Device":
                    fillcolor = "#FFFF00"
                else:
                    fillcolor = "#FFFFFF"
                digraph.node(
                    addr_node,
                    style="filled",
                    color="black",
                    fillcolor=fillcolor,
                    fontname="DejaVu Sans Mono",
                    fontsize="10",
                )
            for addr_pair in addr_pairs:
                digraph.edge(addr_pair[0], addr_pair[1])
            digraph.render()
