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

import argparse
import os


zigator_parser = argparse.ArgumentParser(
    prog="zigator",
    description="Zigator: Security analysis tool for Zigbee networks",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    add_help=True)
zigator_subparsers = zigator_parser.add_subparsers(
    dest="SUBCOMMAND",
    metavar="SUBCOMMAND")

zigator_subparsers.add_parser(
    "print-config",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="print the current configuration")

add_config_entry_parser = zigator_subparsers.add_parser(
    "add-config-entry",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="add a configuration entry")
add_config_entry_parser.add_argument(
    "ENTRY_TYPE",
    type=str.lower,
    choices=["network-key", "link-key", "install-code"],
    action="store",
    help="the type of the configuration entry")
add_config_entry_parser.add_argument(
    "ENTRY_VALUE",
    type=str,
    action="store",
    help="the value of the configuration entry in hexadecimal notation")
add_config_entry_parser.add_argument(
    "ENTRY_NAME",
    type=str,
    action="store",
    help="the name of the configuration entry")

rm_config_entry_parser = zigator_subparsers.add_parser(
    "rm-config-entry",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="remove a configuration entry")
rm_config_entry_parser.add_argument(
    "ENTRY_TYPE",
    type=str.lower,
    choices=["network-key", "link-key", "install-code"],
    action="store",
    help="the type of the configuration entry")
rm_config_entry_parser.add_argument(
    "ENTRY_NAME",
    type=str,
    action="store",
    help="the name of the configuration entry")

parse_parser = zigator_subparsers.add_parser(
    "parse",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="parse pcap files")
parse_parser.add_argument(
    "PCAP_DIRECTORY",
    type=str,
    action="store",
    help="directory with pcap files")
parse_parser.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path for the database file")
parse_parser.add_argument(
    "--num_workers",
    type=int,
    action="store",
    help="the number of workers that will parse pcap files",
    default=argparse.SUPPRESS)

analyze_parser = zigator_subparsers.add_parser(
    "analyze",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="analyze data from a database")
analyze_parser.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path of the database file")
analyze_parser.add_argument(
    "OUTPUT_DIRECTORY",
    type=str,
    action="store",
    help="directory for the output files",
    nargs="?",
    default=os.getcwd())
analyze_parser.add_argument(
    "--num_workers",
    type=int,
    action="store",
    help="the number of workers that will analyze the database",
    default=argparse.SUPPRESS)

visualize_parser = zigator_subparsers.add_parser(
    "visualize",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="visualize data from a database")
visualize_parser.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path of the database file")
visualize_parser.add_argument(
    "OUTPUT_DIRECTORY",
    type=str,
    action="store",
    help="directory for the output files",
    nargs="?",
    default=os.getcwd())

train_parser = zigator_subparsers.add_parser(
    "train",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="train a classifier using data from a database")
train_parser.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path of the database file")
train_parser.add_argument(
    "OUTPUT_DIRECTORY",
    type=str,
    action="store",
    help="directory for the output files",
    nargs="?",
    default=os.getcwd())
train_parser.add_argument(
    "--seed",
    type=int,
    action="store",
    help="seed for the pseudorandom number generator",
    default=argparse.SUPPRESS)
train_parser.add_argument(
    "--restricted",
    action="store_true",
    help="use a restricted set of features")

inject_parser = zigator_subparsers.add_parser(
    "inject",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged packet")
inject_parser.add_argument(
    "FW_PROTOCOL",
    type=str.lower,
    choices=["udp", "sll"],
    action="store",
    help="the protocol that will be used to forward the forged packet")
inject_parser.add_argument(
    "--ipaddr",
    type=str,
    action="store",
    help="the IP address of the UDP server",
    default="127.0.0.1")
inject_parser.add_argument(
    "--portnum",
    type=int,
    action="store",
    help="the port number of the UDP server",
    default=52001)
inject_parser.add_argument(
    "--ifname",
    type=str,
    action="store",
    help="the name of the IEEE 802.15.4 interface",
    default="wpan0")
inject_subparsers = inject_parser.add_subparsers(
    dest="PKT_TYPE",
    metavar="PKT_TYPE")

mpdu_parser = inject_subparsers.add_parser(
    "mpdu",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged MPDU")
mpdu_parser.add_argument(
    "--raw",
    type=str,
    action="store",
    help="the raw bytes of MPDUs in hexadecimal notation",
    default="418889aa990000adde5241576e7f")

beacon_parser = inject_subparsers.add_parser(
    "beacon",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged beacon")
beacon_parser.add_argument(
    "--mac_seqnum",
    type=int,
    action="store",
    help="the MAC sequence number",
    default=137)
beacon_parser.add_argument(
    "--panid",
    type=str,
    action="store",
    help="the PAN ID in hexadecimal notation",
    default="0x99aa")
beacon_parser.add_argument(
    "--srcshortaddr",
    type=str,
    action="store",
    help="the short source address in hexadecimal notation",
    default="0xdead")
beacon_parser.add_argument(
    "--pancoord",
    type=int,
    choices=range(2),
    action="store",
    help="the PAN Coordinator field of beacons",
    default=0)
beacon_parser.add_argument(
    "--assocpermit",
    type=int,
    choices=range(2),
    action="store",
    help="the Association Permit field of beacons",
    default=0)
beacon_parser.add_argument(
    "--devdepth",
    type=int,
    action="store",
    help="the Device Depth field of beacons",
    default=2)
beacon_parser.add_argument(
    "--epid",
    type=str,
    action="store",
    help="the EPID field of beacons in hexadecimal notation",
    default="facefeedbeefcafe")
beacon_parser.add_argument(
    "--updateid",
    type=int,
    action="store",
    help="the Update ID field of beacons",
    default=0)

beaconreq_parser = inject_subparsers.add_parser(
    "beaconreq",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged Beacon Request")
beaconreq_parser.add_argument(
    "--mac_seqnum",
    type=int,
    action="store",
    help="the MAC sequence number",
    default=137)

orphannotif_parser = inject_subparsers.add_parser(
    "orphannotif",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged Orphan Notification")
orphannotif_parser.add_argument(
    "--mac_seqnum",
    type=int,
    action="store",
    help="the MAC sequence number",
    default=137)
orphannotif_parser.add_argument(
    "--srcextendedaddr",
    type=str,
    action="store",
    help="the extended source address in hexadecimal notation",
    default="1122334455667788")

rejoinreq_parser = inject_subparsers.add_parser(
    "rejoinreq",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged Rejoin Request")
rejoinreq_parser.add_argument(
    "--mac_seqnum",
    type=int,
    action="store",
    help="the MAC sequence number",
    default=137)
rejoinreq_parser.add_argument(
    "--panid",
    type=str,
    action="store",
    help="the PAN ID in hexadecimal notation",
    default="0x99aa")
rejoinreq_parser.add_argument(
    "--dstshortaddr",
    type=str,
    action="store",
    help="the short destination address in hexadecimal notation",
    default="0x0000")
rejoinreq_parser.add_argument(
    "--srcshortaddr",
    type=str,
    action="store",
    help="the short source address in hexadecimal notation",
    default="0xdead")
rejoinreq_parser.add_argument(
    "--nwk_seqnum",
    type=int,
    action="store",
    help="the NWK sequence number",
    default=232)
rejoinreq_parser.add_argument(
    "--srcextendedaddr",
    type=str,
    action="store",
    help="the extended source address in hexadecimal notation",
    default="1122334455667788")
rejoinreq_parser.add_argument(
    "--devtype",
    type=int,
    choices=range(2),
    action="store",
    help="the Device Type field of rejoin requests",
    default=0)
rejoinreq_parser.add_argument(
    "--powsrc",
    type=int,
    choices=range(2),
    action="store",
    help="the Power Source field of rejoin requests",
    default=0)
rejoinreq_parser.add_argument(
    "--rxidle",
    type=int,
    choices=range(2),
    action="store",
    help="the Receiver On When Idle field of rejoin requests",
    default=0)

atusb_parser = zigator_subparsers.add_parser(
    "atusb",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="launch selective jamming and spoofing attacks with an ATUSB")
atusb_parser.add_argument(
    "REPO_DIRECTORY",
    type=str,
    action="store",
    help="directory of the repository with the modified ATUSB firmware")

monitor_parser = zigator_subparsers.add_parser(
    "monitor",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="monitor packets from a pcap file continuously")
monitor_parser.add_argument(
    "PCAP_FILEPATH",
    type=str,
    action="store",
    help="path of the pcap file")


def init(derived_version):
    zigator_parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=derived_version)
    zigator_parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="enable debug logging")


def parse_args(args):
    return zigator_parser.parse_args(args)


def print_zigator_help():
    zigator_parser.print_help()


def print_zigator_inject_help():
    inject_parser.print_help()
