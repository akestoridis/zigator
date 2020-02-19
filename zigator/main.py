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


parser = ArgumentParser(
    prog="zigator",
    description="Zigator: Security analysis tool for Zigbee networks",
    add_help=True)
parser.add_argument(
    "-v",
    "--version",
    action="version",
    version="%(prog)s {}".format(zigator.__version__))
parser.add_argument(
    "-d",
    "--debug",
    action="store_true",
    help="enable debug logging")
subparsers = parser.add_subparsers(
    title="subcommands",
    dest="subcommand",
    help="set of valid subcommands")

parser_parse = subparsers.add_parser(
    "parse",
    help="parse pcap files")
parser_parse.add_argument(
    "PCAP_DIRECTORY",
    type=str,
    action="store",
    help="directory with pcap files")
parser_parse.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path for the database file")
parser_parse.add_argument(
    "--network_keys",
    dest="network_filepath",
    type=str,
    action="store",
    help="file with network keys",
    default=None)
parser_parse.add_argument(
    "--link_keys",
    dest="link_filepath",
    type=str,
    action="store",
    help="file with link keys",
    default=None)
parser_parse.add_argument(
    "--install_codes",
    dest="install_filepath",
    type=str,
    action="store",
    help="file with install codes",
    default=None)

parser_analyze = subparsers.add_parser(
    "analyze",
    help="analyze data from a database")
parser_analyze.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path of the database file")
parser_analyze.add_argument(
    "OUTPUT_DIRECTORY",
    type=str,
    action="store",
    help="directory for the output files")


parser_visualize = subparsers.add_parser(
    "visualize",
    help="visualize data from a database")
parser_visualize.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path of the database file")
parser_visualize.add_argument(
    "OUTPUT_DIRECTORY",
    type=str,
    action="store",
    help="directory for the output files")


parser_injectbeacon = subparsers.add_parser(
    "inject-beacon",
    help="inject a Zigbee beacon packet")
parser_injectbeacon.add_argument(
    "PANID",
    type=str,
    action="store",
    help="the PAN ID of the beacon packet")

args = parser.parse_args()


def main():
    """Handle user input and call the required functions."""
    if len(sys.argv) == 1:
        parser.print_help()
        return

    zigator.config.init(args.debug)

    if args.subcommand == "parse":
        if args.network_filepath is not None:
            zigator.config.add_encryption_keys(args.network_filepath,
                                               "network")

        if args.link_filepath is not None:
            zigator.config.add_encryption_keys(args.link_filepath, "link")

        if args.install_filepath is not None:
            zigator.config.add_install_codes(args.install_filepath)

        zigator.parsing.main(args.PCAP_DIRECTORY, args.DATABASE_FILEPATH)
    elif args.subcommand == "analyze":
        zigator.analysis.main(args.DATABASE_FILEPATH, args.OUTPUT_DIRECTORY)
    elif args.subcommand == "visualize":
        zigator.visualization.main(args.DATABASE_FILEPATH,
                                   args.OUTPUT_DIRECTORY)
    elif args.subcommand == "inject-beacon":
        zigator.injection.main("beacon", args.PANID)
    else:
        raise ValueError("Unknown subcommand \"{}\"".format(args.subcommand))


if __name__ == "__main__":
    main()
