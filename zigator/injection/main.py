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

import logging
import socket

from scapy.all import Dot15d4FCS

from .beacon import beacon
from .beaconreq import beaconreq
from .orphannotif import orphannotif
from .rejoinreq import rejoinreq


def main(args):
    """Inject a forged packet."""
    # Forge a packet based on the provided arguments
    if args.PKT_TYPE == "mpdu":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a forged packet may interfere with the  #")
        print("# operation of legitimate IEEE 802.15.4-based networks.    #")
        print("# The users of this tool are responsible for making sure   #")
        print("# that they are compliant with their local laws and that   #")
        print("# they have proper permission from the affected network    #")
        print("# owners.                                                  #")
        print("############################################################")
        answer = input("Are you sure that you want to proceed? [y/N] ")
        # Check the provided answer
        if answer == "y":
            print("You accepted responsibility for your actions")
        else:
            logging.info("Canceling the injection of a forged packet...")
            return
        # Sanity check
        if len(args.phy_payload) < 1 or len(args.phy_payload) > 127:
            raise ValueError("Invalid PHY-layer payload length")
        # Forge the packet
        forged_pkt = Dot15d4FCS(bytes.fromhex(args.phy_payload))
    elif args.PKT_TYPE == "beacon":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a forged beacon may interfere with the  #")
        print("# operation of legitimate IEEE 802.15.4-based networks.    #")
        print("# The users of this tool are responsible for making sure   #")
        print("# that they are compliant with their local laws and that   #")
        print("# they have proper permission from the affected network    #")
        print("# owners.                                                  #")
        print("############################################################")
        answer = input("Are you sure that you want to proceed? [y/N] ")
        # Check the provided answer
        if answer == "y":
            print("You accepted responsibility for your actions")
        else:
            logging.info("Canceling the injection of a forged packet...")
            return
        # Forge the packet
        forged_pkt = beacon(
            args.mac_seqnum, int(args.mac_srcpanid, 16),
            int(args.mac_srcshortaddr, 16), args.mac_beacon_pancoord,
            args.mac_beacon_assocpermit, args.nwk_beacon_devdepth,
            int(args.nwk_beacon_epid, 16), args.nwk_beacon_updateid)
    elif args.PKT_TYPE == "beaconreq":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a Beacon Request may interfere with the #")
        print("# operation of legitimate IEEE 802.15.4-based networks.    #")
        print("# The users of this tool are responsible for making sure   #")
        print("# that they are compliant with their local laws and that   #")
        print("# they have proper permission from the affected network    #")
        print("# owners.                                                  #")
        print("############################################################")
        answer = input("Are you sure that you want to proceed? [y/N] ")
        # Check the provided answer
        if answer == "y":
            print("You accepted responsibility for your actions")
        else:
            logging.info("Canceling the injection of a forged packet...")
            return
        # Forge the packet
        forged_pkt = beaconreq(args.mac_seqnum)
    elif args.PKT_TYPE == "orphannotif":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of an Orphan Notification may interfere    #")
        print("# with the operation of legitimate IEEE 802.15.4-based     #")
        print("# networks. The users of this tool are responsible for     #")
        print("# making sure that they are compliant with their local     #")
        print("# laws and that they have proper permission from the       #")
        print("# affected network owners.                                 #")
        print("############################################################")
        answer = input("Are you sure that you want to proceed? [y/N] ")
        # Check the provided answer
        if answer == "y":
            print("You accepted responsibility for your actions")
        else:
            logging.info("Canceling the injection of a forged packet...")
            return
        # Forge the packet
        forged_pkt = orphannotif(
            args.mac_seqnum, int(args.mac_srcextendedaddr, 16))
    elif args.PKT_TYPE == "rejoinreq":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of an unsecured Rejoin Request may result  #")
        print("# in the disclosure of the network key that a legitimate   #")
        print("# Zigbee network is using and may also interfere with the  #")
        print("# operation of legitimate IEEE 802.15.4-based networks.    #")
        print("# The users of this tool are responsible for making sure   #")
        print("# that they are compliant with their local laws and that   #")
        print("# they have proper permission from the affected network    #")
        print("# owners.                                                  #")
        print("############################################################")
        answer = input("Are you sure that you want to proceed? [y/N] ")
        # Check the provided answer
        if answer == "y":
            print("You accepted responsibility for your actions")
        else:
            logging.info("Canceling the injection of a forged packet...")
            return
        # Forge the packet
        forged_pkt = rejoinreq(
            args.mac_seqnum, int(args.mac_dstpanid, 16),
            int(args.mac_dstshortaddr, 16), int(args.mac_srcshortaddr, 16),
            args.nwk_seqnum, int(args.nwk_srcextendedaddr, 16),
            args.nwk_rejoinreq_devtype, args.nwk_rejoinreq_powsrc,
            args.nwk_rejoinreq_rxidle)
    else:
        raise ValueError("Unknown packet type \"{}\"".format(args.PKT_TYPE))
    logging.info("Forged packet: {}".format(bytes(forged_pkt).hex()))

    # Sanity check
    if len(forged_pkt) < 5 or len(forged_pkt) > 127:
        raise ValueError("Invalid packet length: {}".format(len(forged_pkt)))

    # Forward the forged packet for transmission using the selected protocol
    if args.FW_PROTOCOL == "udp":
        logging.info("IP address: {}".format(args.ipaddr))
        logging.info("Port number: {}".format(args.portnum))
        print("############################################################")
        print("#                          NOTICE                          #")
        print("#                                                          #")
        print("# Before forwarding the forged packet, make sure that the  #")
        print("# transceiver is enabled and properly configured (e.g., it #")
        print("# should already be tuned to the appropriate channel).     #")
        print("############################################################")
        answer = input("Do you want to forward the forged packet? [y/N] ")
        if answer != "y":
            logging.info("Canceling the forwarding of the forged packet...")
            return
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as skt:
            num_bytes_sent = skt.sendto(
                bytes(forged_pkt), (args.ipaddr, args.portnum))
            logging.info("Forwarded {} bytes over UDP".format(num_bytes_sent))
    elif args.FW_PROTOCOL == "sll":
        logging.info("Interface name: {}".format(args.ifname))
        print("############################################################")
        print("#                          NOTICE                          #")
        print("#                                                          #")
        print("# Before forwarding the forged packet, make sure that the  #")
        print("# transceiver is enabled and properly configured (e.g., it #")
        print("# should already be tuned to the appropriate channel).     #")
        print("############################################################")
        answer = input("Do you want to forward the forged packet? [y/N] ")
        if answer != "y":
            logging.info("Canceling the forwarding of the forged packet...")
            return
        with socket.socket(socket.AF_PACKET,
                           socket.SOCK_RAW,
                           socket.htons(0x00f6)) as skt:
            skt.bind((args.ifname, 0))
            num_bytes_sent = skt.send(bytes(forged_pkt)[:-2])
            logging.info("Forwarded {} bytes over SLL".format(num_bytes_sent))
    else:
        raise ValueError("Unknown forwarding protocol \"{}\""
                         "".format(args.FW_PROTOCOL))
