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
import struct

from scapy.all import *

from .. import config


def get_mac_frametype(pkt):
    mac_frametypes = {
            0: "MAC Beacon",
            1: "MAC Data",
            2: "MAC Acknowledgment",
            3: "MAC Command"
    }
    frametype_id = pkt[Dot15d4FCS].fcf_frametype
    return mac_frametypes.get(frametype_id, "Unknown MAC frame type")


def get_mac_security(pkt):
    mac_security_states = {
            0: "MAC Security Disabled",
            1: "MAC Security Enabled"
    }
    sec_state = pkt[Dot15d4FCS].fcf_security
    return mac_security_states.get(sec_state, "Unknown MAC security state")


def get_mac_framepending(pkt):
    mac_framepending_states = {
            0: "No additional packets are pending for the receiver",
            1: "Additional packets are pending for the receiver"
    }
    fp_state = pkt[Dot15d4FCS].fcf_pending
    return mac_framepending_states.get(fp_state, "Unknown MAC FP state")


def get_mac_ackreq(pkt):
    mac_ackreq_states = {
            0: "The sender does not request a MAC Acknowledgment",
            1: "The sender requests a MAC Acknowledgment"
    }
    ar_state = pkt[Dot15d4FCS].fcf_ackreq
    return mac_ackreq_states.get(ar_state, "Unknown MAC AR state")


def get_mac_panidcomp(pkt):
    mac_panidcomp_states = {
            0: "Do not compress the source PAN ID",
            1: "The source PAN ID is the same as the destination PAN ID"
    }
    pc_state = pkt[Dot15d4FCS].fcf_panidcompress
    return mac_panidcomp_states.get(pc_state, "Unknown MAC PC state")


def get_mac_dstaddrmode(pkt):
    mac_dstaddr_modes = {
            0: "No destination MAC address",
            2: "Short destination MAC address",
            3: "Extended destination MAC address"
    }
    dstaddr_mode = pkt[Dot15d4FCS].fcf_destaddrmode
    return mac_dstaddr_modes.get(dstaddr_mode, "Unknown MAC DA mode")


def get_mac_frameversion(pkt):
    mac_frame_versions = {
            0: "IEEE 802.15.4-2003 Frame Version",
            1: "IEEE 802.15-4-2006 Frame Version",
            2: "IEEE 802.15-4-2015 Frame Version"
    }
    fv_id = pkt[Dot15d4FCS].fcf_framever
    return mac_frame_versions.get(fv_id, "Unknown MAC frame version")


def get_mac_srcaddrmode(pkt):
    mac_srcaddr_modes = {
            0: "No source MAC address",
            2: "Short source MAC address",
            3: "Extended source MAC address"
    }
    srcaddr_mode = pkt[Dot15d4FCS].fcf_srcaddrmode
    return mac_srcaddr_modes.get(srcaddr_mode, "Unknown MAC SA mode")


def mac_beacon(pkt):
    # TODO
    return


def mac_command(pkt):
    # TODO
    return


def mac_data(pkt):
    # TODO
    return


def mac_fields(pkt):
    """Parse IEEE 802.15.4 MAC fields."""
    if pkt[Dot15d4FCS].fcs is None:
        config.entry["error_msg"] = (
            "The frame check sequence (FCS) field is not included"
        )
        return

    comp_fcs = struct.unpack("<H", pkt.compute_fcs(raw(pkt)[:-2]))[0]
    if pkt[Dot15d4FCS].fcs != comp_fcs:
        config.entry["error_msg"] = (
            "The received FCS ({}) does not match the computed FCS ({})"
            "".format(hex(pkt[Dot15d4FCS].fcs), hex(comp_fcs))
        )
        return

    config.entry["mac_fcs"] = hex(pkt[Dot15d4FCS].fcs)

    # Frame Control field
    config.entry["mac_frametype"] = get_mac_frametype(pkt)
    config.entry["mac_security"] = get_mac_security(pkt)
    config.entry["mac_framepending"] = get_mac_framepending(pkt)
    config.entry["mac_ackreq"] = get_mac_ackreq(pkt)
    config.entry["mac_panidcomp"] = get_mac_panidcomp(pkt)
    config.entry["mac_dstaddrmode"] = get_mac_dstaddrmode(pkt)
    config.entry["mac_frameversion"] = get_mac_frameversion(pkt)
    config.entry["mac_srcaddrmode"] = get_mac_srcaddrmode(pkt)

    config.entry["mac_seqnum"] = pkt[Dot15d4FCS].seqnum

    if config.entry["mac_security"] == "MAC Security Enabled":
        if pkt.haslayer(Dot15d4AuxSecurityHeader):
            # Zigbee does not utilize any security services on the MAC layer
            logging.warning("The packet #{} in {} is utilizing "
                            "security services on the MAC layer"
                            "".format(config.entry["pkt_num"],
                                      config.entry["pcap_filename"]))
            return
        else:
            config.entry["error_msg"] = (
                "The MAC Auxiliary Security Header is not included"
            )
            return
    elif config.entry["mac_security"] == "MAC Security Disabled":
        if config.entry["mac_frametype"] == "MAC Acknowledgment":
            # MAC Acknowledgments do not use any other fields
            return
        elif config.entry["mac_frametype"] == "MAC Beacon":
            if pkt.haslayer(Dot15d4Beacon):
                mac_beacon(pkt)
            else:
                config.entry["error_msg"] = (
                    "It does not contain MAC Beacon fields"
                )
                return
        elif config.entry["mac_frametype"] == "MAC Command":
            if pkt.haslayer(Dot15d4Cmd):
                mac_command(pkt)
            else:
                config.entry["error_msg"] = (
                    "It does not contain MAC Command fields"
                )
                return
        elif config.entry["mac_frametype"] == "MAC Data":
            if pkt.haslayer(Dot15d4Data):
                return mac_data(pkt)
            else:
                config.entry["error_msg"] = (
                    "It does not contain MAC Data fields"
                )
                return
        else:
            config.entry["error_msg"] = "Unknown MAC frame type"
            return
    else:
        config.entry["error_msg"] = "Unknown MAC security state"
        return
