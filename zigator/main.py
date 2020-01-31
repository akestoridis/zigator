#!/usr/bin/env python3

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

import sys

from argparse import ArgumentParser

import zigator


parser = ArgumentParser(description="Zigator: Security analysis tool "
                                    "for Zigbee networks")
parser.add_argument("--pcap_directory",
                    dest="pcap_directory",
                    type=str,
                    action="store",
                    help="Directory with pcap files",
                    default=None)
parser.add_argument("--network_keys",
                    dest="network_filepath",
                    type=str,
                    action="store",
                    help="File with network keys",
                    default=None)
parser.add_argument("--link_keys",
                    dest="link_filepath",
                    type=str,
                    action="store",
                    help="File with link keys",
                    default=None)
args = parser.parse_args()


def main():
    """Handle user input and call the required functions."""
    if len(sys.argv) == 1:
        parser.print_help()
        return

    if args.network_filepath is not None:
        zigator.config.add_encryption_keys(args.network_filepath, "network")

    if args.link_filepath is not None:
        zigator.config.add_encryption_keys(args.link_filepath, "link")

    if args.pcap_directory is not None:
        zigator.parsing.main(args.pcap_directory)


if __name__ == "__main__":
    main()
