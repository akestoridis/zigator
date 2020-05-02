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
    help="directory for the output files")
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
parser.set_defaults(restricted=False)

parser_inject = subparsers.add_parser(
    "inject",
    help="inject a forged packet over UDP")
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
    choices=range(256),
    action="store",
    metavar="MAC_SEQNUM",
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
    metavar="PANCOORD",
    help="the PAN Coordinator field of beacons",
    default=0)
parser_inject.add_argument(
    "--assocpermit",
    dest="assocpermit",
    type=int,
    choices=range(2),
    action="store",
    metavar="ASSOCPERMIT",
    help="the Association Permit field of beacons",
    default=0)
parser_inject.add_argument(
    "--devdepth",
    dest="devdepth",
    type=int,
    choices=range(16),
    action="store",
    metavar="DEVDEPTH",
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
    choices=range(256),
    action="store",
    metavar="UPDATEID",
    help="the Update ID field of beacons",
    default=0)
parser_inject.add_argument(
    "--nwk_seqnum",
    dest="nwk_seqnum",
    type=int,
    choices=range(256),
    action="store",
    metavar="NWK_SEQNUM",
    help="the NWK sequence number",
    default=232)
parser_inject.add_argument(
    "--devtype",
    dest="devtype",
    type=int,
    choices=range(2),
    action="store",
    metavar="DEVTYPE",
    help="the Device Type field of rejoin requests",
    default=0)
parser_inject.add_argument(
    "--powsrc",
    dest="powsrc",
    type=int,
    choices=range(2),
    action="store",
    metavar="POWSRC",
    help="the Power Source field of rejoin requests",
    default=0)
parser_inject.add_argument(
    "--rxidle",
    dest="rxidle",
    type=int,
    choices=range(2),
    action="store",
    metavar="RXIDLE",
    help="the Receiver On When Idle field of rejoin requests",
    default=0)

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
    elif args.subcommand == "train":
        zigator.training.main("enc-nwk-cmd",
                              args.DATABASE_FILEPATH,
                              args.OUTPUT_DIRECTORY,
                              args.seed,
                              args.restricted)
    elif args.subcommand == "inject":
        zigator.injection.main(args.PKT_TYPE,
                               args.ipaddr,
                               args.portnum,
                               args.raw,
                               args.mac_seqnum,
                               args.panid,
                               args.dstshortaddr,
                               args.srcshortaddr,
                               args.srcextendedaddr,
                               args.pancoord,
                               args.assocpermit,
                               args.devdepth,
                               args.epid,
                               args.updateid,
                               args.nwk_seqnum,
                               args.devtype,
                               args.powsrc,
                               args.rxidle)
    else:
        raise ValueError("Unknown subcommand \"{}\"".format(args.subcommand))


if __name__ == "__main__":
    main()
