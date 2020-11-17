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

"""
Command-line interface for the zigator package
"""

import os

from argparse import ArgumentParser


parser = ArgumentParser(
    prog="zigator",
    description="Zigator: Security analysis tool for Zigbee networks",
    add_help=True)


def init(derived_version):
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=derived_version)
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="enable debug logging")
    subparsers = parser.add_subparsers(
        title="subcommands",
        dest="subcommand",
        help="set of valid subcommands")

    subparsers.add_parser(
        "print-config",
        help="print the current configuration")

    parser_add_config_entry = subparsers.add_parser(
        "add-config-entry",
        help="add a configuration entry")
    parser_add_config_entry.add_argument(
        "ENTRY_TYPE",
        type=str,
        choices=["network-key", "link-key", "install-code"],
        action="store",
        help="the type of the configuration entry")
    parser_add_config_entry.add_argument(
        "ENTRY_VALUE",
        type=str,
        action="store",
        help="the value of the configuration entry in hexadecimal notation")
    parser_add_config_entry.add_argument(
        "ENTRY_NAME",
        type=str,
        action="store",
        help="the name of the configuration entry")

    parser_rm_config_entry = subparsers.add_parser(
        "rm-config-entry",
        help="remove a configuration entry")
    parser_rm_config_entry.add_argument(
        "ENTRY_TYPE",
        type=str,
        choices=["network-key", "link-key", "install-code"],
        action="store",
        help="the type of the configuration entry")
    parser_rm_config_entry.add_argument(
        "ENTRY_NAME",
        type=str,
        action="store",
        help="the name of the configuration entry")

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
        "--num_workers",
        type=int,
        action="store",
        help="the number of workers that will parse pcap files",
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
        help="directory for the output files",
        nargs="?",
        default=os.getcwd())
    parser_analyze.add_argument(
        "--num_workers",
        type=int,
        action="store",
        help="the number of workers that will analyze the database",
        default=None)

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
        help="directory for the output files",
        nargs="?",
        default=os.getcwd())

    parser_train = subparsers.add_parser(
        "train",
        help="train a classifier using data from a database")
    parser_train.add_argument(
        "DATABASE_FILEPATH",
        type=str,
        action="store",
        help="path of the database file")
    parser_train.add_argument(
        "OUTPUT_DIRECTORY",
        type=str,
        action="store",
        help="directory for the output files",
        nargs="?",
        default=os.getcwd())
    parser_train.add_argument(
        "--seed",
        type=int,
        action="store",
        help="seed for the pseudorandom number generator",
        default=None)
    parser_train.add_argument(
        "--restricted",
        dest="restricted",
        action="store_true",
        help="use a restricted set of features")
    parser_train.add_argument(
        "--unrestricted",
        dest="restricted",
        action="store_false",
        help="use an unrestricted set of features")
    parser_train.set_defaults(restricted=False)

    parser_inject = subparsers.add_parser(
        "inject",
        help="inject a forged packet")
    parser_inject.add_argument(
        "FW_PROTOCOL",
        type=str,
        choices=["udp", "sll"],
        action="store",
        help="the protocol that will be used to forward the forged packet")
    parser_inject.add_argument(
        "PKT_TYPE",
        type=str,
        choices=["mpdu", "beacon", "beaconreq", "orphannotif", "rejoinreq"],
        action="store",
        help="the type of the forged packet")
    parser_inject.add_argument(
        "--ipaddr",
        dest="ipaddr",
        type=str,
        action="store",
        help="the IP address of the UDP server",
        default="127.0.0.1")
    parser_inject.add_argument(
        "--portnum",
        dest="portnum",
        type=int,
        action="store",
        help="the port number of the UDP server",
        default=52001)
    parser_inject.add_argument(
        "--ifname",
        dest="ifname",
        type=str,
        action="store",
        help="the name of the IEEE 802.15.4 interface",
        default="wpan0")
    parser_inject.add_argument(
        "--raw",
        dest="raw",
        type=str,
        action="store",
        help="the raw bytes of MPDUs in hexadecimal notation",
        default=None)
    parser_inject.add_argument(
        "--mac_seqnum",
        dest="mac_seqnum",
        type=int,
        action="store",
        help="the MAC sequence number",
        default=137)
    parser_inject.add_argument(
        "--panid",
        dest="panid",
        type=str,
        action="store",
        help="the PAN ID in hexadecimal notation",
        default=None)
    parser_inject.add_argument(
        "--dstshortaddr",
        dest="dstshortaddr",
        type=str,
        action="store",
        help="the short destination address in hexadecimal notation",
        default=None)
    parser_inject.add_argument(
        "--srcshortaddr",
        dest="srcshortaddr",
        type=str,
        action="store",
        help="the short source address in hexadecimal notation",
        default=None)
    parser_inject.add_argument(
        "--srcextendedaddr",
        dest="srcextendedaddr",
        type=str,
        action="store",
        help="the extended source address in hexadecimal notation",
        default=None)
    parser_inject.add_argument(
        "--pancoord",
        dest="pancoord",
        type=int,
        choices=range(2),
        action="store",
        help="the PAN Coordinator field of beacons",
        default=0)
    parser_inject.add_argument(
        "--assocpermit",
        dest="assocpermit",
        type=int,
        choices=range(2),
        action="store",
        help="the Association Permit field of beacons",
        default=0)
    parser_inject.add_argument(
        "--devdepth",
        dest="devdepth",
        type=int,
        action="store",
        help="the Device Depth field of beacons",
        default=2)
    parser_inject.add_argument(
        "--epid",
        dest="epid",
        type=str,
        action="store",
        help="the EPID field of beacons in hexadecimal notation",
        default=None)
    parser_inject.add_argument(
        "--updateid",
        dest="updateid",
        type=int,
        action="store",
        help="the Update ID field of beacons",
        default=0)
    parser_inject.add_argument(
        "--nwk_seqnum",
        dest="nwk_seqnum",
        type=int,
        action="store",
        help="the NWK sequence number",
        default=232)
    parser_inject.add_argument(
        "--devtype",
        dest="devtype",
        type=int,
        choices=range(2),
        action="store",
        help="the Device Type field of rejoin requests",
        default=0)
    parser_inject.add_argument(
        "--powsrc",
        dest="powsrc",
        type=int,
        choices=range(2),
        action="store",
        help="the Power Source field of rejoin requests",
        default=0)
    parser_inject.add_argument(
        "--rxidle",
        dest="rxidle",
        type=int,
        choices=range(2),
        action="store",
        help="the Receiver On When Idle field of rejoin requests",
        default=0)

    parser_atusb = subparsers.add_parser(
        "atusb",
        help="launch selective jamming and spoofing attacks with an ATUSB")
    parser_atusb.add_argument(
        "REPO_DIRECTORY",
        type=str,
        action="store",
        help="directory of the repository with the modified ATUSB firmware")

    parser_monitor = subparsers.add_parser(
        "monitor",
        help="monitor packets from a pcap file continuously")
    parser_monitor.add_argument(
        "PCAP_FILEPATH",
        type=str,
        action="store",
        help="path of the pcap file")


def parse_args(args):
    return parser.parse_args(args)


def print_help():
    parser.print_help()
