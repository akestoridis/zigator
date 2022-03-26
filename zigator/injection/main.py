# Copyright (C) 2020-2022 Dimitrios-Georgios Akestoridis
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
from time import sleep

from scapy.all import (
    Dot15d4FCS,
    LoWPANFragmentationFirst,
    LoWPANFragmentationSubsequent,
)

from ..enums import Protocol
from .activeepreq import activeepreq
from .beaconreq import beaconreq
from .childupdatereq import childupdatereq
from .deviceannce import deviceannce
from .firstfrag import firstfrag
from .orphannotif import orphannotif
from .rejoinreq import rejoinreq
from .subseqfrag import subseqfrag
from .threadbeacon import threadbeacon
from .updatedevice import updatedevice
from .zigbeebeacon import zigbeebeacon


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
        if len(args.phy_payload) < 2 or len(args.phy_payload) > 254:
            raise ValueError("Invalid PHY-layer payload length")
        # Forge the packet
        forged_pkt = Dot15d4FCS(bytes.fromhex(args.phy_payload))
    elif args.PKT_TYPE == "zigbeebeacon":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a forged Zigbee beacon may interfere    #")
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
        forged_pkt = zigbeebeacon(
            args.mac_seqnum,
            int(args.mac_srcpanid, 16),
            int(args.mac_srcshortaddr, 16),
            args.mac_beacon_pancoord,
            args.mac_beacon_assocpermit,
            args.nwk_beacon_devdepth,
            int(args.nwk_beacon_epid, 16),
            args.nwk_beacon_updateid,
        )
    elif args.PKT_TYPE == "threadbeacon":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a forged Thread beacon may interfere    #")
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
        forged_pkt = threadbeacon(
            args.mac_seqnum,
            int(args.mac_srcpanid, 16),
            int(args.mac_srcextendedaddr, 16),
            args.thr_beacon_version,
            args.thr_beacon_native,
            args.thr_beacon_joining,
            args.thr_beacon_networkname,
            int(args.thr_beacon_epid, 16),
            bytes.fromhex(args.thr_beacon_payload),
        )
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
            args.mac_seqnum,
            int(args.mac_srcextendedaddr, 16),
        )
    elif args.PKT_TYPE == "rejoinreq":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a Rejoin Request may result in the      #")
        print("# disclosure of the network key that a legitimate Zigbee   #")
        print("# network is using and may also interfere with the         #")
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
            args.mac_seqnum,
            int(args.mac_dstpanid, 16),
            int(args.mac_dstshortaddr, 16),
            int(args.mac_srcshortaddr, 16),
            args.nwk_seqnum,
            int(args.nwk_srcextendedaddr, 16),
            args.nwk_rejoinreq_devtype,
            args.nwk_rejoinreq_powsrc,
            args.nwk_rejoinreq_rxidle,
            args.nwk_security,
            args.nwk_aux_framecounter,
            args.nwk_aux_keyseqnum,
            bytes.fromhex(args.nwk_key),
        )
    elif args.PKT_TYPE == "updatedevice":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of an Update-Device command may interfere  #")
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
        forged_pkt = updatedevice(
            args.mac_seqnum,
            int(args.mac_dstpanid, 16),
            int(args.mac_dstshortaddr, 16),
            int(args.mac_srcshortaddr, 16),
            int(args.nwk_dstshortaddr, 16),
            int(args.nwk_srcshortaddr, 16),
            args.nwk_radius,
            args.nwk_seqnum,
            args.aps_counter,
            int(args.aps_updatedevice_extendedaddr, 16),
            int(args.aps_updatedevice_shortaddr, 16),
            args.aps_updatedevice_status,
            args.nwk_aux_framecounter,
            int(args.nwk_aux_srcaddr, 16),
            args.nwk_aux_keyseqnum,
            bytes.fromhex(args.nwk_key),
            args.aps_security,
            bool(args.aps_aux_extnonce),
            args.aps_aux_framecounter,
            int(args.aps_aux_srcaddr, 16),
            bytes.fromhex(args.aps_key),
        )
    elif args.PKT_TYPE == "deviceannce":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a Device_annce command may interfere    #")
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
        forged_pkt = deviceannce(
            args.mac_seqnum,
            int(args.mac_dstpanid, 16),
            int(args.mac_srcshortaddr, 16),
            args.nwk_seqnum,
            int(args.nwk_srcextendedaddr, 16),
            args.aps_counter,
            args.zdp_seqnum,
            args.nwk_aux_framecounter,
            args.nwk_aux_keyseqnum,
            bytes.fromhex(args.nwk_key),
        )
    elif args.PKT_TYPE == "activeepreq":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of an Active_EP_req command may interfere  #")
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
        forged_pkt = activeepreq(
            args.mac_seqnum,
            int(args.mac_dstpanid, 16),
            int(args.mac_dstshortaddr, 16),
            args.nwk_seqnum,
            args.aps_counter,
            args.zdp_seqnum,
            args.nwk_aux_framecounter,
            int(args.nwk_aux_srcaddr, 16),
            args.nwk_aux_keyseqnum,
            bytes.fromhex(args.nwk_key),
        )
    elif args.PKT_TYPE == "firstfrag":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a forged first fragment may interfere   #")
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
        forged_pkt = firstfrag(
            args.mac_seqnum,
            int(args.mac_dstpanid, 16),
            int(args.mac_dstextendedaddr, 16),
            int(args.mac_srcextendedaddr, 16),
            args.thr_firstfrag_datagramsize,
            int(args.thr_firstfrag_datagramtag, 16),
            bytes.fromhex(args.thr_firstfrag_payload),
            args.thr_iphc_hlim,
            None
            if not hasattr(args, "thr_iphc_hoplimit")
            else args.thr_iphc_hoplimit,
            args.thr_nhcudp_sport,
            args.thr_nhcudp_dport,
            int(args.thr_nhcudp_checksum, 16),
            args.mac_security,
            args.mac_aux_seclevel,
            args.mac_aux_keyidmode,
            args.mac_aux_framecounter,
            None
            if not hasattr(args, "mac_aux_keysource")
            else int(args.mac_aux_keysource, 16),
            None
            if not hasattr(args, "mac_aux_keyindex")
            else int(args.mac_aux_keyindex, 16),
            bytes.fromhex(args.mac_key),
            int(args.mac_noncesrcaddr, 16),
        )
    elif args.PKT_TYPE == "subseqfrag":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a forged subsequent fragment may        #")
        print("# interfere with the operation of legitimate               #")
        print("# IEEE 802.15.4-based networks. The users of this tool are #")
        print("# responsible for making sure that they are compliant with #")
        print("# their local laws and that they have proper permission    #")
        print("# from the affected network owners.                        #")
        print("############################################################")
        answer = input("Are you sure that you want to proceed? [y/N] ")
        # Check the provided answer
        if answer == "y":
            print("You accepted responsibility for your actions")
        else:
            logging.info("Canceling the injection of a forged packet...")
            return
        # Forge the packet
        forged_pkt = subseqfrag(
            args.mac_framepending,
            args.mac_seqnum,
            int(args.mac_dstpanid, 16),
            int(args.mac_dstextendedaddr, 16),
            int(args.mac_srcextendedaddr, 16),
            args.thr_subseqfrag_datagramsize,
            int(args.thr_subseqfrag_datagramtag, 16),
            args.thr_subseqfrag_datagramoffset,
            bytes.fromhex(args.thr_subseqfrag_payload),
            args.mac_security,
            args.mac_aux_seclevel,
            args.mac_aux_keyidmode,
            args.mac_aux_framecounter,
            None
            if not hasattr(args, "mac_aux_keysource")
            else int(args.mac_aux_keysource, 16),
            None
            if not hasattr(args, "mac_aux_keyindex")
            else int(args.mac_aux_keyindex, 16),
            bytes.fromhex(args.mac_key),
            int(args.mac_noncesrcaddr, 16),
        )
    elif args.PKT_TYPE == "childupdatereq":
        # Print a disclaimer
        print("############################################################")
        print("#                        DISCLAIMER                        #")
        print("#                                                          #")
        print("# The injection of a forged Child Update Request may       #")
        print("# interfere with the operation of legitimate               #")
        print("# IEEE 802.15.4-based networks. The users of this tool are #")
        print("# responsible for making sure that they are compliant with #")
        print("# their local laws and that they have proper permission    #")
        print("# from the affected network owners.                        #")
        print("############################################################")
        answer = input("Are you sure that you want to proceed? [y/N] ")
        # Check the provided answer
        if answer == "y":
            print("You accepted responsibility for your actions")
        else:
            logging.info("Canceling the injection of a forged packet...")
            return
        # Forge the packet
        forged_pkt = childupdatereq(
            args.mac_seqnum,
            int(args.mac_dstpanid, 16),
            int(args.mac_dstextendedaddr, 16),
            int(args.mac_srcextendedaddr, 16),
            int(args.thr_nhcudp_checksum, 16),
            bytes.fromhex(args.mle_cmd_payload),
            args.mle_aux_seclevel,
            args.mle_aux_keyidmode,
            args.mle_aux_framecounter,
            None
            if not hasattr(args, "mle_aux_keysource")
            else int(args.mle_aux_keysource, 16),
            None
            if not hasattr(args, "mle_aux_keyindex")
            else int(args.mle_aux_keyindex, 16),
            bytes.fromhex(args.mle_key),
            int(args.mle_noncesrcaddr, 16),
        )
    else:
        raise ValueError("Unknown packet type \"{}\"".format(args.PKT_TYPE))
    logging.info("Forged packet: {}".format(bytes(forged_pkt).hex()))

    # Sanity check
    if len(forged_pkt) < 5 or len(forged_pkt) > 127:
        raise ValueError("Invalid packet length: {}".format(len(forged_pkt)))

    # Forward the forged packet for transmission using the selected protocol
    if args.FW_PROTOCOL == Protocol.UDP:
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
            if not hasattr(args, "flood_rate"):
                num_bytes_sent = skt.sendto(
                    bytes(forged_pkt),
                    (args.ipaddr, args.portnum),
                )
                logging.info(
                    "Forwarded {} bytes over UDP".format(num_bytes_sent),
                )
            else:
                logging.info(
                    "Forwarding a forged packet "
                    + "every {} seconds ".format(args.flood_rate)
                    + "until the interrupt key (Ctrl-C) is hit...",
                )
                try:
                    while True:
                        skt.sendto(
                            bytes(forged_pkt),
                            (args.ipaddr, args.portnum),
                        )
                        sleep(args.flood_rate)
                        forged_pkt = update_forged_pkt(
                            args.PKT_TYPE,
                            forged_pkt,
                        )
                except KeyboardInterrupt:
                    logging.info("Stopped forwarding forged packets")
    elif args.FW_PROTOCOL == Protocol.SLL:
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
        with socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x00f6),
        ) as skt:
            skt.bind((args.ifname, 0))
            if not hasattr(args, "flood_rate"):
                num_bytes_sent = skt.send(bytes(forged_pkt)[:-2])
                logging.info(
                    "Forwarded {} bytes over SLL".format(num_bytes_sent),
                )
            else:
                logging.info(
                    "Forwarding a forged packet "
                    + "every {} seconds ".format(args.flood_rate)
                    + "until the interrupt key (Ctrl-C) is hit...",
                )
                try:
                    while True:
                        skt.send(bytes(forged_pkt)[:-2])
                        sleep(args.flood_rate)
                        forged_pkt = update_forged_pkt(
                            args.PKT_TYPE,
                            forged_pkt,
                        )
                except KeyboardInterrupt:
                    logging.info("Stopped forwarding forged packets")
    else:
        raise ValueError(
            "Unknown forwarding protocol \"{}\"".format(args.FW_PROTOCOL),
        )


def update_forged_pkt(pkt_type, forged_pkt):
    # Update type-dependent fields of the forged packet
    if pkt_type == "firstfrag":
        forged_pkt[LoWPANFragmentationFirst].datagramTag = (
            (forged_pkt[LoWPANFragmentationFirst].datagramTag + 1) % 0x10000
        )
    elif pkt_type == "subseqfrag":
        forged_pkt[LoWPANFragmentationSubsequent].datagramTag = (
            (forged_pkt[LoWPANFragmentationSubsequent].datagramTag + 1)
            % 0x10000
        )

    # Update the MAC Sequence Number field of the forged packet
    forged_pkt[Dot15d4FCS].seqnum = (
        (forged_pkt[Dot15d4FCS].seqnum + 1) % 0x100
    )

    # Update the Frame Check Sequence (FCS) field of the forged packet
    forged_pkt[Dot15d4FCS].fcs = int.from_bytes(
        forged_pkt.compute_fcs(bytes(forged_pkt)[:-2]),
        byteorder="little",
    )

    return forged_pkt
