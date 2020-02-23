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

import graphviz

from .. import config


def network_graphs(out_dirpath):
    """Generate a network graph for each pcap file."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Get the path of each pcap file
    pcap_filepaths = config.db.fetch_values(
        [
            "pcap_directory",
            "pcap_filename"
        ],
        None,
        True
    )

    for pcap_filepath in pcap_filepaths:
        # Get the addresses of nodes that have exchanged MAC Data packets
        addr_pairs = config.db.fetch_values(
            [
                "mac_srcshortaddr",
                "mac_dstshortaddr",
            ],
            [
                ("pcap_directory", pcap_filepath[0]),
                ("pcap_filename", pcap_filepath[1]),
                ("mac_frametype", "MAC Data"),
                ("!mac_dstshortaddr", "0xffff"),
                ("error_msg", None),
            ],
            True
        )

        # Render a directed graph from the observed address pairs
        digraph = graphviz.Digraph(
            name=os.path.splitext(pcap_filepath[1])[0],
            comment=os.path.join(pcap_filepath[0], pcap_filepath[1]),
            directory=out_dirpath,
            format="pdf",
            engine="dot")
        for addr_pair in addr_pairs:
            digraph.edge(addr_pair[0], addr_pair[1])
        digraph.render()
