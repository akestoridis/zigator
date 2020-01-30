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


def get_nwk_aux_seclevel(pkt):
    sec_levels = {
        0: "None",
        1: "MIC-32",
        2: "MIC-64",
        3: "MIC-128",
        4: "ENC",
        5: "ENC-MIC-32",
        6: "ENC-MIC-64",
        7: "ENC-MIC-128"
    }
    seclevel_id = pkt[ZigbeeSecurityHeader].nwk_seclevel
    return sec_levels.get(seclevel_id, "Unknown NWK security level")


def get_nwk_aux_keytype(pkt):
    key_types = {
        0: "Data Key",
        1: "Network Key",
        2: "Key-Transport Key",
        3: "Key-Load Key"
    }
    keytype_id = pkt[ZigbeeSecurityHeader].key_type
    return key_types.get(keytype_id, "Unknown NWK key type")


def get_nwk_aux_extnonce(pkt):
    extnonce_states = {
        0: "The source address is not present",
        1: "The source address is present"
    }
    extnonce_state = pkt[ZigbeeSecurityHeader].extended_nonce
    return extnonce_states.get(extnonce_state, "Unknown NWK EN state")


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
    return


def nwk_auxiliary(pkt):
    # Security Control field
    config.entry["nwk_aux_seclevel"] = get_nwk_aux_seclevel(pkt)
    config.entry["nwk_aux_keytype"] = get_nwk_aux_keytype(pkt)
    config.entry["nwk_aux_extnonce"] = get_nwk_aux_extnonce(pkt)

    # Frame Counter field
    config.entry["nwk_aux_framecounter"] = pkt[ZigbeeSecurityHeader].fc
    frame_counter = pkt[ZigbeeSecurityHeader].fc

    # Source Address field
    if (config.entry["nwk_aux_extnonce"]
            == "The source address is present"):
        config.entry["nwk_aux_srcaddr"] = hex(
            pkt[ZigbeeSecurityHeader].source)
        potential_sources = set([pkt[ZigbeeSecurityHeader].source])
    elif (config.entry["nwk_aux_extnonce"]
            == "The source address is not present"):
        potential_sources = set()
        if config.entry["nwk_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["nwk_srcextendedaddr"], 16))
        if config.entry["mac_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["mac_srcextendedaddr"], 16))
    else:
        config.entry["error_msg"] = "Unknown NWK EN state"
        return

    # Key Sequence Number field
    if config.entry["nwk_aux_keytype"] == "Network Key":
        config.entry["nwk_aux_keyseqnum"] = (
            pkt[ZigbeeSecurityHeader].key_seqnum
        )
        key_seqnum = pkt[ZigbeeSecurityHeader].key_seqnum
        potential_keys = config.network_keys
    else:
        config.entry["error_msg"] = "Unexpected key type on the NWK layer"
        return

    # TODO: Attempt to decrypt the payload
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
