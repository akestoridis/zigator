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

from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigbeeSecurityHeader

from .. import config


def get_aps_frametype(pkt):
    aps_frame_types = {
        0: "APS Data",
        1: "APS Command",
        2: "APS Acknowledgment",
        3: "APS Inter-PAN"
    }
    frametype_id = pkt[ZigbeeAppDataPayload].aps_frametype
    return aps_frame_types.get(frametype_id, "Unknown APS frame type")


def get_aps_delmode(pkt):
    aps_delivery_modes = {
        0: "Normal unicast delivery",
        2: "Broadcast",
        3: "Group addressing"
    }
    delmode_id = pkt[ZigbeeAppDataPayload].delivery_mode
    return aps_delivery_modes.get(delmode_id, "Unknown APS delivery mode")


def get_aps_fragmentation(pkt):
    aps_frag_state = {
        0: "No fragmentation",
        1: "First fragment",
        2: "Continued fragment"
    }
    frag_state = pkt[ZigbeeAppDataPayload].fragmentation
    return aps_frag_state.get(frag_state, "Unknown APS fragmentation")


def aps_data_header(pkt):
    if (config.entry["aps_delmode"] == "Normal unicast delivery"
            or config.entry["aps_delmode"] == "Broadcast"):
        # Destination Endpoint field
        config.entry["aps_dstendpoint"] = (
            pkt[ZigbeeAppDataPayload].dst_endpoint
        )
    elif config.entry["aps_delmode"] == "Group addressing":
        # Group Address field
        config.entry["aps_groupaddr"] = hex(
            pkt[ZigbeeAppDataPayload].group_addr)
    else:
        config.entry["error_msg"] = "Unknown APS delivery mode"
        return

    # Cluster Identifier field
    config.entry["aps_clusterid"] = hex(pkt[ZigbeeAppDataPayload].cluster)

    # Profile Identifier field
    config.entry["aps_profileid"] = hex(pkt[ZigbeeAppDataPayload].profile)

    # Source Endpoint field
    config.entry["aps_srcendpoint"] = pkt[ZigbeeAppDataPayload].src_endpoint

    # APS Counter field
    config.entry["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    # Extended Header field
    if config.entry["aps_exthdr"] == "The extended header is included":
        # Extended Frame Control field
        config.entry["aps_fragmentation"] = get_aps_fragmentation(pkt)

        # Block Number field
        if (config.entry["aps_fragmentation"] == "First fragment"
                or config.entry["aps_fragmentation"] == "Continued fragment"):
            config.entry["aps_blocknumber"] = (
                pkt[ZigbeeAppDataPayload].block_number
            )
        elif config.entry["aps_fragmentation"] != "No fragmentation":
            config.entry["error_msg"] = "Unknown APS fragmentation"
            return
    elif config.entry["aps_exthdr"] != "The extended header is not included":
        config.entry["error_msg"] = "Unknown extended header state"
        return

    if config.entry["aps_security"] == "APS Security Enabled":
        if pkt.haslayer(ZigbeeSecurityHeader):
            # TODO: aps_auxiliary(pkt)
            return
        else:
            config.entry["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.entry["aps_security"] == "APS Security Disabled":
        # TODO: aps_data_payload(pkt)
        return
    else:
        config.entry["error_msg"] = "Unknown APS security state"
        return


def aps_command_header(pkt):
    # APS Counter field
    config.entry["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    if config.entry["aps_security"] == "APS Security Enabled":
        if pkt.haslayer(ZigbeeSecurityHeader):
            # TODO: aps_auxiliary(pkt)
            return
        else:
            config.entry["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.entry["aps_security"] == "APS Security Disabled":
        # TODO: aps_command_payload(pkt)
        return
    else:
        config.entry["error_msg"] = "Unknown APS security state"
        return


def aps_ack_header(pkt):
    if config.entry["aps_ackformat"] == "APS ACK Format Disabled":
        # Destination Endpoint field
        config.entry["aps_dstendpoint"] = (
            pkt[ZigbeeAppDataPayload].dst_endpoint
        )

        # Cluster Identifier field
        config.entry["aps_clusterid"] = hex(pkt[ZigbeeAppDataPayload].cluster)

        # Profile Identifier field
        config.entry["aps_profileid"] = hex(pkt[ZigbeeAppDataPayload].profile)

        # Source Endpoint field
        config.entry["aps_srcendpoint"] = (
            pkt[ZigbeeAppDataPayload].src_endpoint
        )
    elif config.entry["aps_ackformat"] != "APS ACK Format Enabled":
        config.entry["error_msg"] = "Unknown ACK Format state"
        return

    # APS Counter field
    config.entry["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    # Extended Header field
    if config.entry["aps_exthdr"] == "The extended header is included":
        # Extended Frame Control field
        config.entry["aps_fragmentation"] = get_aps_fragmentation(pkt)

        # Block Number field
        if (config.entry["aps_fragmentation"] == "First fragment"
                or config.entry["aps_fragmentation"] == "Continued fragment"):
            config.entry["aps_blocknumber"] = (
                pkt[ZigbeeAppDataPayload].block_number
            )

            # ACK Bitfield
            config.entry["aps_ackbitfield"] = (
                pkt[ZigbeeAppDataPayload].ack_bitfield
            )
        elif config.entry["aps_fragmentation"] != "No fragmentation":
            config.entry["error_msg"] = "Unknown APS fragmentation"
            return
    elif config.entry["aps_exthdr"] != "The extended header is not included":
        config.entry["error_msg"] = "Unknown extended header state"
        return

    if config.entry["aps_security"] == "APS Security Enabled":
        if pkt.haslayer(ZigbeeSecurityHeader):
            # TODO: aps_auxiliary(pkt)
            return
        else:
            config.entry["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.entry["aps_security"] == "APS Security Disabled":
        # APS Acknowledgments do not contain any other fields
        return
    else:
        config.entry["error_msg"] = "Unknown APS security state"
        return


def aps_fields(pkt):
    """Parse Zigbee APS fields."""
    # Frame Control field
    config.entry["aps_frametype"] = get_aps_frametype(pkt)
    config.entry["aps_delmode"] = get_aps_delmode(pkt)
    if pkt[ZigbeeAppDataPayload].frame_control.ack_format:
        config.entry["aps_ackformat"] = "APS ACK Format Enabled"
    else:
        config.entry["aps_ackformat"] = "APS ACK Format Disabled"
    if pkt[ZigbeeAppDataPayload].frame_control.security:
        config.entry["aps_security"] = "APS Security Enabled"
    else:
        config.entry["aps_security"] = "APS Security Disabled"
    if pkt[ZigbeeAppDataPayload].frame_control.ack_req:
        config.entry["aps_ackreq"] = "The sender requests an APS ACK"
    else:
        config.entry["aps_ackreq"] = "The sender does not request an APS ACK"
    if pkt[ZigbeeAppDataPayload].frame_control.extended_hdr:
        config.entry["aps_exthdr"] = "The extended header is included"
    else:
        config.entry["aps_exthdr"] = "The extended header is not included"

    if config.entry["aps_frametype"] == "APS Data":
        aps_data_header(pkt)
    elif config.entry["aps_frametype"] == "APS Command":
        aps_command_header(pkt)
    elif config.entry["aps_frametype"] == "APS Acknowledgment":
        aps_ack_header(pkt)
    elif config.entry["aps_frametype"] == "APS Inter-PAN":
        logging.warning("Packet #{} in {} contains Inter-PAN fields"
                        "which were ignored"
                        "".format(config.entry["pkt_num"],
                                  config.entry["pcap_filename"]))
        config.entry["error_msg"] = "Ignored the Inter-PAN fields"
        return
    else:
        config.entry["error_msg"] = "Unknown APS frame type"
