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
    "--phy_payload",
    type=str,
    action="store",
    help="the PHY-layer payload in hexadecimal notation",
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
    "--mac_srcpanid",
    type=str,
    action="store",
    help="the source PAN ID in hexadecimal notation",
    default="0x99aa")
beacon_parser.add_argument(
    "--mac_srcshortaddr",
    type=str,
    action="store",
    help="the short source MAC address in hexadecimal notation",
    default="0xdead")
beacon_parser.add_argument(
    "--mac_beacon_pancoord",
    type=int,
    choices=range(2),
    action="store",
    help="the PAN Coordinator beacon field value",
    default=0)
beacon_parser.add_argument(
    "--mac_beacon_assocpermit",
    type=int,
    choices=range(2),
    action="store",
    help="the Association Permit beacon field value",
    default=0)
beacon_parser.add_argument(
    "--nwk_beacon_devdepth",
    type=int,
    action="store",
    help="the Device Depth beacon field value",
    default=2)
beacon_parser.add_argument(
    "--nwk_beacon_epid",
    type=str,
    action="store",
    help="the Extended PAN ID beacon field value in hexadecimal notation",
    default="facefeedbeefcafe")
beacon_parser.add_argument(
    "--nwk_beacon_updateid",
    type=int,
    action="store",
    help="the Update ID beacon field value",
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
    "--mac_srcextendedaddr",
    type=str,
    action="store",
    help="the extended source MAC address in hexadecimal notation",
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
    "--mac_dstpanid",
    type=str,
    action="store",
    help="the destination PAN ID in hexadecimal notation",
    default="0x99aa")
rejoinreq_parser.add_argument(
    "--mac_dstshortaddr",
    type=str,
    action="store",
    help="the short destination MAC address in hexadecimal notation",
    default="0x0000")
rejoinreq_parser.add_argument(
    "--mac_srcshortaddr",
    type=str,
    action="store",
    help="the short source MAC address in hexadecimal notation",
    default="0xdead")
rejoinreq_parser.add_argument(
    "--nwk_seqnum",
    type=int,
    action="store",
    help="the NWK sequence number",
    default=232)
rejoinreq_parser.add_argument(
    "--nwk_srcextendedaddr",
    type=str,
    action="store",
    help="the extended source NWK address in hexadecimal notation",
    default="1122334455667788")
rejoinreq_parser.add_argument(
    "--nwk_rejoinreq_devtype",
    type=int,
    choices=range(2),
    action="store",
    help="the Device Type rejoin request field value",
    default=0)
rejoinreq_parser.add_argument(
    "--nwk_rejoinreq_powsrc",
    type=int,
    choices=range(2),
    action="store",
    help="the Power Source rejoin request field value",
    default=0)
rejoinreq_parser.add_argument(
    "--nwk_rejoinreq_rxidle",
    type=int,
    choices=range(2),
    action="store",
    help="the Receiver On When Idle rejoin request field value",
    default=0)
rejoinreq_parser.add_argument(
    "--nwk_security",
    type=int,
    choices=range(2),
    action="store",
    help="the NWK security field value",
    default=0)
rejoinreq_parser.add_argument(
    "--nwk_aux_framecounter",
    type=int,
    action="store",
    help="the NWK auxiliary frame counter",
    default=10000)
rejoinreq_parser.add_argument(
    "--nwk_aux_keyseqnum",
    type=int,
    action="store",
    help="the NWK auxiliary key sequence number",
    default=0)
rejoinreq_parser.add_argument(
    "--nwk_key",
    type=str,
    action="store",
    help="the network key in hexadecimal notation",
    default="11111111111111111111111111111111")

updatedevice_parser = inject_subparsers.add_parser(
    "updatedevice",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged Update-Device command")
updatedevice_parser.add_argument(
    "--mac_seqnum",
    type=int,
    action="store",
    help="the MAC sequence number",
    default=137)
updatedevice_parser.add_argument(
    "--mac_dstpanid",
    type=str,
    action="store",
    help="the destination PAN ID in hexadecimal notation",
    default="0x99aa")
updatedevice_parser.add_argument(
    "--mac_dstshortaddr",
    type=str,
    action="store",
    help="the short destination MAC address in hexadecimal notation",
    default="0x0000")
updatedevice_parser.add_argument(
    "--mac_srcshortaddr",
    type=str,
    action="store",
    help="the short source MAC address in hexadecimal notation",
    default="0xdead")
updatedevice_parser.add_argument(
    "--nwk_dstshortaddr",
    type=str,
    action="store",
    help="the short destination NWK address in hexadecimal notation",
    default="0x0000")
updatedevice_parser.add_argument(
    "--nwk_srcshortaddr",
    type=str,
    action="store",
    help="the short source NWK address in hexadecimal notation",
    default="0xdead")
updatedevice_parser.add_argument(
    "--nwk_radius",
    type=int,
    action="store",
    help="the NWK radius",
    default=30)
updatedevice_parser.add_argument(
    "--nwk_seqnum",
    type=int,
    action="store",
    help="the NWK sequence number",
    default=232)
updatedevice_parser.add_argument(
    "--aps_counter",
    type=int,
    action="store",
    help="the APS counter",
    default=210)
updatedevice_parser.add_argument(
    "--aps_updatedevice_extendedaddr",
    type=str,
    action="store",
    help="the extended Update-Device address in hexadecimal notation",
    default="7777770000000004")
updatedevice_parser.add_argument(
    "--aps_updatedevice_shortaddr",
    type=str,
    action="store",
    help="the short Update-Device address in hexadecimal notation",
    default="0x2201")
updatedevice_parser.add_argument(
    "--aps_updatedevice_status",
    type=int,
    choices=range(4),
    action="store",
    help="the Update-Device status field value",
    default=1)
updatedevice_parser.add_argument(
    "--nwk_aux_framecounter",
    type=int,
    action="store",
    help="the NWK auxiliary frame counter",
    default=10000)
updatedevice_parser.add_argument(
    "--nwk_aux_srcaddr",
    type=str,
    action="store",
    help="the NWK auxiliary extended source address in hexadecimal notation",
    default="7777770000000003")
updatedevice_parser.add_argument(
    "--nwk_aux_keyseqnum",
    type=int,
    action="store",
    help="the NWK auxiliary key sequence number",
    default=0)
updatedevice_parser.add_argument(
    "--nwk_key",
    type=str,
    action="store",
    help="the network key in hexadecimal notation",
    default="11111111111111111111111111111111")
updatedevice_parser.add_argument(
    "--aps_security",
    type=int,
    choices=range(2),
    action="store",
    help="the APS security field value",
    default=0)
updatedevice_parser.add_argument(
    "--aps_aux_extnonce",
    type=int,
    choices=range(2),
    action="store",
    help="the APS auxiliary extended nonce field value",
    default=1)
updatedevice_parser.add_argument(
    "--aps_aux_framecounter",
    type=int,
    action="store",
    help="the APS auxiliary frame counter",
    default=4096)
updatedevice_parser.add_argument(
    "--aps_aux_srcaddr",
    type=str,
    action="store",
    help="the APS auxiliary extended source address in hexadecimal notation",
    default="7777770000000003")
updatedevice_parser.add_argument(
    "--aps_key",
    type=str,
    action="store",
    help="the link key in hexadecimal notation",
    default="33333333333333333333333333333333")

deviceannce_parser = inject_subparsers.add_parser(
    "deviceannce",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged Device_annce")
deviceannce_parser.add_argument(
    "--mac_seqnum",
    type=int,
    action="store",
    help="the MAC sequence number",
    default=137)
deviceannce_parser.add_argument(
    "--mac_dstpanid",
    type=str,
    action="store",
    help="the destination PAN ID in hexadecimal notation",
    default="0x99aa")
deviceannce_parser.add_argument(
    "--mac_srcshortaddr",
    type=str,
    action="store",
    help="the short source MAC address in hexadecimal notation",
    default="0xdead")
deviceannce_parser.add_argument(
    "--nwk_seqnum",
    type=int,
    action="store",
    help="the NWK sequence number",
    default=232)
deviceannce_parser.add_argument(
    "--nwk_srcextendedaddr",
    type=str,
    action="store",
    help="the extended source NWK address in hexadecimal notation",
    default="1122334455667788")
deviceannce_parser.add_argument(
    "--aps_counter",
    type=int,
    action="store",
    help="the APS counter",
    default=12)
deviceannce_parser.add_argument(
    "--zdp_seqnum",
    type=int,
    action="store",
    help="the ZDP sequence number",
    default=129)
deviceannce_parser.add_argument(
    "--nwk_aux_framecounter",
    type=int,
    action="store",
    help="the NWK auxiliary frame counter",
    default=10000)
deviceannce_parser.add_argument(
    "--nwk_aux_keyseqnum",
    type=int,
    action="store",
    help="the NWK auxiliary key sequence number",
    default=0)
deviceannce_parser.add_argument(
    "--nwk_key",
    type=str,
    action="store",
    help="the network key in hexadecimal notation",
    default="11111111111111111111111111111111")

activeepreq_parser = inject_subparsers.add_parser(
    "activeepreq",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="inject a forged Active_EP_req")
activeepreq_parser.add_argument(
    "--mac_seqnum",
    type=int,
    action="store",
    help="the MAC sequence number",
    default=137)
activeepreq_parser.add_argument(
    "--mac_dstpanid",
    type=str,
    action="store",
    help="the destination PAN ID in hexadecimal notation",
    default="0x99aa")
activeepreq_parser.add_argument(
    "--mac_dstshortaddr",
    type=str,
    action="store",
    help="the short destination MAC address in hexadecimal notation",
    default="0xdead")
activeepreq_parser.add_argument(
    "--nwk_seqnum",
    type=int,
    action="store",
    help="the NWK sequence number",
    default=232)
activeepreq_parser.add_argument(
    "--aps_counter",
    type=int,
    action="store",
    help="the APS counter",
    default=12)
activeepreq_parser.add_argument(
    "--zdp_seqnum",
    type=int,
    action="store",
    help="the ZDP sequence number",
    default=129)
activeepreq_parser.add_argument(
    "--nwk_aux_framecounter",
    type=int,
    action="store",
    help="the NWK auxiliary frame counter",
    default=10000)
activeepreq_parser.add_argument(
    "--nwk_aux_srcaddr",
    type=str,
    action="store",
    help="the NWK auxiliary extended source address in hexadecimal notation",
    default="1122334455667788")
activeepreq_parser.add_argument(
    "--nwk_aux_keyseqnum",
    type=int,
    action="store",
    help="the NWK auxiliary key sequence number",
    default=0)
activeepreq_parser.add_argument(
    "--nwk_key",
    type=str,
    action="store",
    help="the network key in hexadecimal notation",
    default="11111111111111111111111111111111")

atusb_parser = zigator_subparsers.add_parser(
    "atusb",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="launch selective jamming and spoofing attacks with an ATUSB")
atusb_parser.add_argument(
    "REPO_DIRECTORY",
    type=str,
    action="store",
    help="directory of the repository with the modified ATUSB firmware")

wids_parser = zigator_subparsers.add_parser(
    "wids",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    help="operate as a WIDS sensor")
wids_parser.add_argument(
    "SENSOR_ID",
    type=str,
    action="store",
    help="identifier for the WIDS sensor")
wids_parser.add_argument(
    "PANID",
    type=str,
    action="store",
    help="the PAN ID of the user's network in hexadecimal notation")
wids_parser.add_argument(
    "EPID",
    type=str,
    action="store",
    help="the Extended PAN ID of the user's network in hexadecimal notation")
wids_parser.add_argument(
    "DATABASE_FILEPATH",
    type=str,
    action="store",
    help="path for the database file")
wids_parser.add_argument(
    "OUTPUT_DIRECTORY",
    type=str,
    action="store",
    help="directory for the output files",
    nargs="?",
    default=os.path.join(os.getcwd(), "wids-output"))
wids_parser.add_argument(
    "--ifname",
    type=str,
    action="store",
    help="the name of the IEEE 802.15.4 interface",
    default="wpan0")
wids_parser.add_argument(
    "--pcap_period",
    type=float,
    action="store",
    help="the maximum number of seconds of traffic for each pcap file",
    default=3600.0)
wids_parser.add_argument(
    "--num_zip_files",
    type=int,
    action="store",
    help="the maximum positive number of concurrently stored zip files",
    default=16)
wids_parser.add_argument(
    "--link_key_names",
    type=str,
    action="store",
    help="the names of link keys that ideally should not be used",
    nargs="*",
    default=[])
wids_parser.add_argument(
    "--table_thres",
    type=int,
    action="store",
    help="the number of rows that will trigger table reduction",
    default=argparse.SUPPRESS)
wids_parser.add_argument(
    "--table_reduct",
    type=int,
    action="store",
    help="the number of rows that will be deleted whenever triggered",
    default=argparse.SUPPRESS)
wids_parser.add_argument(
    "--ipaddr",
    type=str,
    action="store",
    help="the IP address of the WIDS sensor",
    default=argparse.SUPPRESS)
wids_parser.add_argument(
    "--portnum",
    type=int,
    action="store",
    help="the port number of the WIDS sensor",
    default=argparse.SUPPRESS)


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
