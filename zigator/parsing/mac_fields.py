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

import struct

from scapy.all import Dot15d4AuxSecurityHeader
from scapy.all import Dot15d4Beacon
from scapy.all import Dot15d4Cmd
from scapy.all import Dot15d4CmdAssocReq
from scapy.all import Dot15d4CmdAssocResp
from scapy.all import Dot15d4CmdCoordRealign
from scapy.all import Dot15d4CmdCoordRealignPage
from scapy.all import Dot15d4CmdDisassociation
from scapy.all import Dot15d4CmdGTSReq
from scapy.all import Dot15d4Data
from scapy.all import Dot15d4FCS
from scapy.all import ZigBeeBeacon
from scapy.all import ZigbeeNWK

from .. import config
from .mac_getters import get_mac_ackreq
from .mac_getters import get_mac_assocreq_allocaddr
from .mac_getters import get_mac_assocreq_apc
from .mac_getters import get_mac_assocreq_devtype
from .mac_getters import get_mac_assocreq_powsrc
from .mac_getters import get_mac_assocreq_rxidle
from .mac_getters import get_mac_assocreq_seccap
from .mac_getters import get_mac_assocrsp_status
from .mac_getters import get_mac_beacon_assocpermit
from .mac_getters import get_mac_beacon_pancoord
from .mac_getters import get_mac_command
from .mac_getters import get_mac_disassoc_reason
from .mac_getters import get_mac_dstaddrmode
from .mac_getters import get_mac_framepending
from .mac_getters import get_mac_frametype
from .mac_getters import get_mac_frameversion
from .mac_getters import get_mac_gtsreq_chartype
from .mac_getters import get_mac_gtsreq_dir
from .mac_getters import get_mac_panidcomp
from .mac_getters import get_mac_security
from .mac_getters import get_mac_srcaddrmode
from .nwk_fields import nwk_fields


def mac_assocreq(pkt):
    # Capability Information field (1 byte)
    config.entry["mac_assocreq_apc"] = get_mac_assocreq_apc(pkt)
    config.entry["mac_assocreq_devtype"] = get_mac_assocreq_devtype(pkt)
    config.entry["mac_assocreq_powsrc"] = get_mac_assocreq_powsrc(pkt)
    config.entry["mac_assocreq_rxidle"] = get_mac_assocreq_rxidle(pkt)
    config.entry["mac_assocreq_seccap"] = get_mac_assocreq_seccap(pkt)
    config.entry["mac_assocreq_allocaddr"] = get_mac_assocreq_allocaddr(pkt)

    return


def mac_assocrsp(pkt):
    # Short Address field (2 bytes)
    config.entry["mac_assocrsp_shortaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdAssocResp].short_address)

    # Association Status field (1 byte)
    config.entry["mac_assocrsp_status"] = get_mac_assocrsp_status(pkt)

    return


def mac_disassoc(pkt):
    # Disassociation Reason field (1 byte)
    config.entry["mac_disassoc_reason"] = get_mac_disassoc_reason(pkt)

    return


def mac_realign(pkt):
    # PAN Identifier field (2 bytes)
    config.entry["mac_realign_panid"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].panid)

    # Coordinator Short Address field (2 bytes)
    config.entry["mac_realign_coordaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].coord_address)

    # Channel Number field (1 byte)
    config.entry["mac_realign_channel"] = pkt[Dot15d4CmdCoordRealign].channel

    # Short Address field (2 bytes)
    config.entry["mac_realign_shortaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].dev_address)

    # Channel Page field (0/1 byte)
    if pkt.haslayer(Dot15d4CmdCoordRealignPage):
        config.entry["mac_realign_page"] = (
            pkt[Dot15d4CmdCoordRealignPage].channel_page
        )


def mac_gtsreq(pkt):
    # GTS Characteristics field (1 byte)
    config.entry["mac_gtsreq_length"] = pkt[Dot15d4CmdGTSReq].gts_len
    config.entry["mac_gtsreq_dir"] = get_mac_gtsreq_dir(pkt)
    config.entry["mac_gtsreq_chartype"] = get_mac_gtsreq_chartype(pkt)

    return


def mac_command(pkt, msg_queue):
    # Destination Addressing fields (0/4/10 bytes)
    if (config.entry["mac_dstaddrmode"]
            == "Short destination MAC address"):
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_panid)
        config.entry["mac_dstshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_addr)
    elif (config.entry["mac_dstaddrmode"]
            == "Extended destination MAC address"):
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_panid)
        config.entry["mac_dstextendedaddr"] = format(
            pkt[Dot15d4Cmd].dest_addr, "016x")
    elif (config.entry["mac_dstaddrmode"]
            != "No destination MAC address"):
        config.entry["error_msg"] = "Unknown MAC DA mode"
        return

    # Source Addressing fields (0/2/4/8/10 bytes)
    if (config.entry["mac_srcaddrmode"]
            == "Short source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Cmd].src_panid)
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].src_addr)
    elif (config.entry["mac_srcaddrmode"]
            == "Extended source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Cmd].src_panid)
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Cmd].src_addr, "016x")
    elif (config.entry["mac_srcaddrmode"]
            != "No source MAC address"):
        config.entry["error_msg"] = "Unknown MAC SA mode"
        return

    # Command Frame Identifier field (1 byte)
    config.entry["mac_cmd_id"] = get_mac_command(pkt)

    # Compute the MAC Command Payload Length
    # The constant 6 was derived by summing the following:
    #  2: MAC Frame Control
    #  1: MAC Sequence Number
    #  1: MAC Command Frame Identifier
    #  2: MAC Frame Check Sequence
    config.entry["mac_cmd_payloadlength"] = config.entry["phy_length"] - 6
    # Compute the length of the MAC Destination Addressing fields
    if (config.entry["mac_dstaddrmode"]
            == "Short destination MAC address"):
        config.entry["mac_cmd_payloadlength"] -= 4
    elif (config.entry["mac_dstaddrmode"]
            == "Extended destination MAC address"):
        config.entry["mac_cmd_payloadlength"] -= 10
    elif (config.entry["mac_dstaddrmode"]
            != "No destination MAC address"):
        config.entry["error_msg"] = "Unknown MAC DA mode"
        return
    # Compute the length of the MAC Source Addressing fields
    if (config.entry["mac_srcaddrmode"]
            == "Short source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["mac_cmd_payloadlength"] -= 2
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["mac_cmd_payloadlength"] -= 2
    elif (config.entry["mac_srcaddrmode"]
            == "Extended source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["mac_cmd_payloadlength"] -= 2
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["mac_cmd_payloadlength"] -= 8
    elif (config.entry["mac_srcaddrmode"]
            != "No source MAC address"):
        config.entry["error_msg"] = "Unknown MAC SA mode"
        return
    # Compute the length of the MAC Auxiliary Security Header field
    if config.entry["mac_security"] == "MAC Security Enabled":
        msg_queue.put(
            (config.DEBUG_MSG,
             "Ignored packet #{} in {} because it utilizes "
             "security services on the MAC layer"
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"])))
        config.entry["error_msg"] = (
            "Ignored MAC command with enabled MAC-layer security"
        )
        return
    elif config.entry["mac_security"] != "MAC Security Disabled":
        config.entry["error_msg"] = "Unknown MAC security state"
        return

    # Command Payload field (variable)
    if config.entry["mac_cmd_id"] == "MAC Association Request":
        mac_assocreq(pkt)
        return
    elif config.entry["mac_cmd_id"] == "MAC Association Response":
        mac_assocrsp(pkt)
        return
    elif config.entry["mac_cmd_id"] == "MAC Disassociation Notification":
        mac_disassoc(pkt)
        return
    elif config.entry["mac_cmd_id"] == "MAC Data Request":
        # MAC Data Requests do not contain any other fields
        return
    elif config.entry["mac_cmd_id"] == "MAC PAN ID Conflict Notification":
        # MAC PAN ID Conflict Notifications do not contain any other fields
        return
    elif config.entry["mac_cmd_id"] == "MAC Orphan Notification":
        # MAC Orphan Notifications do not contain any other fields
        return
    elif config.entry["mac_cmd_id"] == "MAC Beacon Request":
        # MAC Beacon Requests do not contain any other fields
        return
    elif config.entry["mac_cmd_id"] == "MAC Coordinator Realignment":
        mac_realign(pkt)
        return
    elif config.entry["mac_cmd_id"] == "MAC GTS Request":
        mac_gtsreq(pkt)
        return
    else:
        config.entry["error_msg"] = "Unknown MAC Command"
        return


def mac_beacon(pkt, msg_queue):
    if config.entry["mac_panidcomp"] != "Do not compress the source PAN ID":
        config.entry["error_msg"] = (
            "The source PAN ID of MAC Beacons should not be compressed"
        )
        return
    elif config.entry["mac_dstaddrmode"] != "No destination MAC address":
        config.entry["error_msg"] = (
            "MAC Beacons should not contain a destination PAN ID and address"
        )
        return

    # Addressing fields (4/10 bytes)
    config.entry["mac_srcpanid"] = "0x{:04x}".format(
        pkt[Dot15d4Beacon].src_panid)
    if config.entry["mac_srcaddrmode"] == "Short source MAC address":
        config.entry["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Beacon].src_addr)
    elif config.entry["mac_srcaddrmode"] == "Extended source MAC address":
        config.entry["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Beacon].src_addr, "016x")
    elif config.entry["mac_srcaddrmode"] == "No source MAC address":
        config.entry["error_msg"] = (
            "MAC Beacons should contain a source PAN ID and address"
        )
        return
    else:
        config.entry["error_msg"] = "Unknown MAC SA mode"
        return

    # Superframe Specification field (2 bytes)
    config.entry["mac_beacon_beaconorder"] = pkt[Dot15d4Beacon].sf_beaconorder
    config.entry["mac_beacon_sforder"] = pkt[Dot15d4Beacon].sf_sforder
    config.entry["mac_beacon_finalcap"] = pkt[Dot15d4Beacon].sf_finalcapslot
    config.entry["mac_beacon_ble"] = pkt[Dot15d4Beacon].sf_battlifeextend
    config.entry["mac_beacon_pancoord"] = get_mac_beacon_pancoord(pkt)
    config.entry["mac_beacon_assocpermit"] = get_mac_beacon_assocpermit(pkt)

    # GTS Specification field (1 byte)
    config.entry["mac_beacon_gtsnum"] = pkt[Dot15d4Beacon].gts_spec_desccount
    config.entry["mac_beacon_gtspermit"] = pkt[Dot15d4Beacon].gts_spec_permit

    # GTS Directions Mask field (0/1 byte)
    if config.entry["mac_beacon_gtsnum"] > 0:
        config.entry["mac_beacon_gtsmask"] = pkt[Dot15d4Beacon].gts_dir_mask

    # GTS List field (variable)
    if config.entry["mac_beacon_gtsnum"] > 0:
        msg_queue.put(
            (config.DEBUG_MSG,
             "Packet #{} in {} contains a GTS List field "
             "which could not be processed"
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"])))
        config.entry["error_msg"] = "Could not process the GTS List"
        return

    # Pending Address Specification field (1 byte)
    config.entry["mac_beacon_nsap"] = pkt[Dot15d4Beacon].pa_num_short
    config.entry["mac_beacon_neap"] = pkt[Dot15d4Beacon].pa_num_long

    # Address List field (variable)
    config.entry["mac_beacon_shortaddresses"] = ",".join("0x{:04x}".format(
        addr) for addr in pkt[Dot15d4Beacon].pa_short_addresses)
    config.entry["mac_beacon_extendedaddresses"] = ",".join(format(
        addr, "016x") for addr in pkt[Dot15d4Beacon].pa_long_addresses)

    # Beacon Payload field (variable)
    if pkt.haslayer(ZigBeeBeacon):
        nwk_fields(pkt, msg_queue)
        return
    else:
        config.entry["error_msg"] = (
            "There is no beacon payload from the Zigbee NWK layer"
        )
        return


def mac_data(pkt, msg_queue):
    # Destination Addressing fields (0/4/10 bytes)
    if (config.entry["mac_dstaddrmode"]
            == "Short destination MAC address"):
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_panid)
        config.entry["mac_dstshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_addr)
    elif (config.entry["mac_dstaddrmode"]
            == "Extended destination MAC address"):
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_panid)
        config.entry["mac_dstextendedaddr"] = format(
            pkt[Dot15d4Data].dest_addr, "016x")
    elif (config.entry["mac_dstaddrmode"]
            != "No destination MAC address"):
        config.entry["error_msg"] = "Unknown MAC DA mode"
        return

    # Source Addressing fields (0/2/4/8/10 bytes)
    if (config.entry["mac_srcaddrmode"]
            == "Short source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Data].src_panid)
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Data].src_addr)
    elif (config.entry["mac_srcaddrmode"]
            == "Extended source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Data].src_panid)
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Data].src_addr, "016x")
    elif (config.entry["mac_srcaddrmode"]
            != "No source MAC address"):
        config.entry["error_msg"] = "Unknown MAC SA mode"
        return

    # Data Payload field (variable)
    if pkt.haslayer(ZigbeeNWK):
        nwk_fields(pkt, msg_queue)
        return
    else:
        config.entry["error_msg"] = "There are no Zigbee NWK fields"
        return


def mac_fields(pkt, msg_queue):
    """Parse IEEE 802.15.4 MAC fields."""
    config.entry["mac_show"] = pkt.show(dump=True)
    if pkt[Dot15d4FCS].fcs is None:
        config.entry["error_msg"] = (
            "PE201: The frame check sequence (FCS) field is not included"
        )
        return

    comp_fcs = struct.unpack("<H", pkt.compute_fcs(bytes(pkt)[:-2]))[0]
    if pkt[Dot15d4FCS].fcs != comp_fcs:
        msg_queue.put(
            (config.DEBUG_MSG,
             "The received FCS (0x{:04x}), for packet #{} in {}, "
             "does not match the computed FCS (0x{:04x})"
             "".format(pkt[Dot15d4FCS].fcs,
                       config.entry["pkt_num"],
                       config.entry["pcap_filename"],
                       comp_fcs)))
        config.entry["error_msg"] = (
            "PE202: Incorrect frame check sequence (FCS)"
        )
        return

    # Frame Check Sequence field (2 bytes)
    config.entry["mac_fcs"] = "0x{:04x}".format(pkt[Dot15d4FCS].fcs)

    # Frame Control field (2 bytes)
    config.entry["mac_frametype"] = get_mac_frametype(pkt)
    config.entry["mac_security"] = get_mac_security(pkt)
    config.entry["mac_framepending"] = get_mac_framepending(pkt)
    config.entry["mac_ackreq"] = get_mac_ackreq(pkt)
    config.entry["mac_panidcomp"] = get_mac_panidcomp(pkt)
    config.entry["mac_dstaddrmode"] = get_mac_dstaddrmode(pkt)
    config.entry["mac_frameversion"] = get_mac_frameversion(pkt)
    config.entry["mac_srcaddrmode"] = get_mac_srcaddrmode(pkt)

    # Sequence Number field (1 byte)
    config.entry["mac_seqnum"] = pkt[Dot15d4FCS].seqnum

    if config.entry["mac_security"] == "MAC Security Enabled":
        # Auxiliary Security Header field (0/5/6/10/14 bytes)
        if pkt.haslayer(Dot15d4AuxSecurityHeader):
            # Zigbee does not utilize any security services on the MAC layer
            msg_queue.put(
                (config.DEBUG_MSG,
                 "The packet #{} in {} is utilizing "
                 "security services on the MAC layer"
                 "".format(config.entry["pkt_num"],
                           config.entry["pcap_filename"])))
            config.entry["error_msg"] = (
                "Ignored the MAC Auxiliary Security Header"
            )
            return
        else:
            config.entry["error_msg"] = (
                "The MAC Auxiliary Security Header is not included"
            )
            return
    elif config.entry["mac_security"] == "MAC Security Disabled":
        # MAC Payload field (variable)
        if config.entry["mac_frametype"] == "MAC Acknowledgment":
            # MAC Acknowledgments do not contain any other fields
            return
        elif config.entry["mac_frametype"] == "MAC Command":
            if pkt.haslayer(Dot15d4Cmd):
                mac_command(pkt, msg_queue)
                return
            else:
                config.entry["error_msg"] = (
                    "There are no MAC Command fields"
                )
                return
        elif config.entry["mac_frametype"] == "MAC Beacon":
            if pkt.haslayer(Dot15d4Beacon):
                mac_beacon(pkt, msg_queue)
                return
            else:
                config.entry["error_msg"] = (
                    "There are no MAC Beacon fields"
                )
                return
        elif config.entry["mac_frametype"] == "MAC Data":
            if pkt.haslayer(Dot15d4Data):
                mac_data(pkt, msg_queue)
                return
            else:
                config.entry["error_msg"] = (
                    "There are no MAC Data fields"
                )
                return
        else:
            config.entry["error_msg"] = "Unknown MAC frame type"
            return
    else:
        config.entry["error_msg"] = "Unknown MAC security state"
        return
