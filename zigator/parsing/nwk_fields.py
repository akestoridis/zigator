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

from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigBeeBeacon
from scapy.all import ZigbeeNWK
from scapy.all import ZigbeeNWKCommandPayload
from scapy.all import ZigbeeSecurityHeader

from .. import config


def get_nwk_frametype(pkt):
    nwk_frame_types = {
            0: "NWK Data",
            1: "NWK Command",
            3: "NWK Inter-PAN"
    }
    frametype_id = pkt[ZigbeeNWK].frametype
    return nwk_frame_types.get(frametype_id, "Unknown NWK frame type")


def get_nwk_protocolversion(pkt):
    protocol_versions = {
            1: "Zigbee 2004",
            2: "Zigbee PRO",
            3: "Zigbee Green Power"
    }
    if pkt.haslayer(ZigbeeNWK):
        prot_ver = pkt[ZigbeeNWK].proto_version
    elif pkt.haslayer(ZigBeeBeacon):
        prot_ver = pkt[ZigBeeBeacon].nwkc_protocol_version
    else:
        prot_ver = None
    return protocol_versions.get(prot_ver, "Unknown NWK protocol version")


def get_nwk_discroute(pkt):
    discroute_states = {
            0: "Suppress route discovery",
            1: "Enable route discovery"
    }
    discroute_state = pkt[ZigbeeNWK].discover_route
    return discroute_states.get(discroute_state, "Unknown NWK DR state")


def nwk_command(pkt):
    # TODO
    return


def nwk_beacon(pkt):
    config.entry["nwk_beacon_protocolid"] = pkt[ZigBeeBeacon].proto_id
    config.entry["nwk_beacon_stackprofile"] = pkt[ZigBeeBeacon].stack_profile
    config.entry["nwk_beacon_protocolversion"] = get_nwk_protocolversion(pkt)
    config.entry["nwk_beacon_routercap"] = pkt[ZigBeeBeacon].router_capacity
    config.entry["nwk_beacon_devdepth"] = pkt[ZigBeeBeacon].device_depth
    config.entry["nwk_beacon_edcap"] = pkt[ZigBeeBeacon].end_device_capacity
    config.entry["nwk_beacon_epid"] = hex(pkt[ZigBeeBeacon].extended_pan_id)
    config.entry["nwk_beacon_txoffset"] = pkt[ZigBeeBeacon].tx_offset
    config.entry["nwk_beacon_updateid"] = pkt[ZigBeeBeacon].update_id


def nwk_auxiliary(pkt):
    # TODO
    return


def nwk_fields(pkt):
    """Parse Zigbee NWK fields."""
    if config.entry["mac_frametype"] == "MAC Beacon":
        nwk_beacon(pkt)
        return
    elif config.entry["mac_frametype"] != "MAC Data":
        logging.warning("Packet #{} in {} contains unknown NWK fields"
                        "".format(config.entry["pkt_num"],
                                  config.entry["pcap_filename"]))
        config.entry["error_msg"] = "Unknown NWK fields"
        return

    # Frame Control field
    config.entry["nwk_frametype"] = get_nwk_frametype(pkt)
    config.entry["nwk_protocolversion"] = get_nwk_protocolversion(pkt)
    config.entry["nwk_discroute"] = get_nwk_discroute(pkt)
    if pkt[ZigbeeNWK].flags.multicast:
        config.entry["nwk_multicast"] = "NWK Multicast Enabled"
    else:
        config.entry["nwk_multicast"] = "NWK Multicast Disabled"
    if pkt[ZigbeeNWK].flags.security:
        config.entry["nwk_security"] = "NWK Security Enabled"
    else:
        config.entry["nwk_security"] = "NWK Security Disabled"
    if pkt[ZigbeeNWK].flags.source_route:
        config.entry["nwk_srcroute"] = "NWK Source Route Included"
    else:
        config.entry["nwk_srcroute"] = "NWK Source Route Omitted"
    if pkt[ZigbeeNWK].flags.extended_dst:
        config.entry["nwk_extendeddst"] = "NWK Extended Destination Included"
    else:
        config.entry["nwk_extendeddst"] = "NWK Extended Destination Omitted"
    if pkt[ZigbeeNWK].flags.extended_src:
        config.entry["nwk_extendedsrc"] = "NWK Extended Source Included"
    else:
        config.entry["nwk_extendedsrc"] = "NWK Extended Source Omitted"
    if pkt[ZigbeeNWK].flags.reserved1:
        config.entry["nwk_edinitiator"] = "NWK End Device Initiator"
    else:
        config.entry["nwk_edinitiator"] = "NWK Not End Device Initiator"

    # Short Destination Address field
    config.entry["nwk_dstshortaddr"] = hex(pkt[ZigbeeNWK].destination)

    # Short Source Address field
    config.entry["nwk_srcshortaddr"] = hex(pkt[ZigbeeNWK].source)

    # Radius field
    config.entry["nwk_radius"] = pkt[ZigbeeNWK].radius

    # Sequence Number field
    config.entry["nwk_seqnum"] = pkt[ZigbeeNWK].seqnum

    # Extended Destination field
    if (config.entry["nwk_extendeddst"]
            == "NWK Extended Destination Included"):
        config.entry["nwk_dstextendedaddr"] = hex(pkt[ZigbeeNWK].ext_dst)
    elif (config.entry["nwk_extendeddst"]
            != "NWK Extended Destination Omitted"):
        config.entry["error_msg"] = "Unknown Extended Destination state"
        return

    # Extended Source field
    if (config.entry["nwk_extendedsrc"]
            == "NWK Extended Source Included"):
        config.entry["nwk_srcextendedaddr"] = hex(pkt[ZigbeeNWK].ext_src)
    elif (config.entry["nwk_extendedsrc"]
            != "NWK Extended Source Omitted"):
        config.entry["error_msg"] = "Unknown Extended Source state"
        return

    # Multicast Control field
    if config.entry["nwk_multicast"] == "NWK Multicast Enabled":
        logging.warning("Packet #{} in {} contains a Multicast Control field "
                        "which could not be processed"
                        "".format(config.entry["pkt_num"],
                                  config.entry["pcap_filename"]))
        config.entry["error_msg"] = "Could not process the Multicast Control"
        return
    elif config.entry["nwk_multicast"] != "NWK Multicast Disabled":
        config.entry["error_msg"] = "Unknown Multicast state"
        return

    # Source Route Subframe field
    if config.entry["nwk_srcroute"] == "NWK Source Route Included":
        config.entry["nwk_srcroute_relaycount"] = pkt[ZigbeeNWK].relay_count
        config.entry["nwk_srcroute_relayindex"] = pkt[ZigbeeNWK].relay_index
        config.entry["nwk_srcroute_relaylist"] = ",".join(
            "0x{:04X}".format(addr) for addr in pkt[ZigbeeNWK].relays)
    elif config.entry["nwk_srcroute"] != "NWK Source Route Omitted":
        config.entry["error_msg"] = "Unknown Source Route state"
        return

    if config.entry["nwk_security"] == "NWK Security Enabled":
        if pkt.haslayer(ZigbeeSecurityHeader):
            nwk_auxiliary(pkt)
            return
        else:
            config.entry["error_msg"] = (
                "The NWK Auxiliary Header is not included"
            )
            return
    elif config.entry["nwk_security"] == "NWK Security Disabled":
        if config.entry["nwk_frametype"] == "NWK Command":
            if pkt.haslayer(ZigbeeNWKCommandPayload):
                nwk_command(pkt)
                return
            else:
                config.entry["error_msg"] = (
                    "It does not contain NWK Command fields"
                )
                return
        elif config.entry["nwk_frametype"] == "NWK Inter-PAN":
            logging.warning("Packet #{} in {} contains Inter-PAN fields"
                            "which were ignored"
                            "".format(config.entry["pkt_num"],
                                      config.entry["pcap_filename"]))
            config.entry["error_msg"] = "Ignored the Inter-PAN fields"
            return
        elif config.entry["nwk_frametype"] == "NWK Data":
            if pkt.haslayer(ZigbeeAppDataPayload):
                # TODO: aps_fields(pkt)
                return
            else:
                config.entry["error_msg"] = (
                    "It does not contain Zigbee APS fields"
                )
                return
        else:
            config.entry["error_msg"] = "Unknown NWK frame type"
            return
    else:
        config.entry["error_msg"] = "Unknown NWK security state"
        return
