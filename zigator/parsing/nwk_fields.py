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

import logging

from scapy.all import (
    ZigBeeBeacon,
    ZigbeeAppDataPayload,
    ZigbeeNWK,
    ZigbeeNWKCommandPayload,
    ZigbeeSecurityHeader,
)

from .. import (
    config,
    crypto,
)
from ..enums import Message
from .aps_fields import aps_fields


NWK_FRAME_TYPES = {
    0: "0b00: NWK Data",
    1: "0b01: NWK Command",
    3: "0b11: NWK Inter-PAN",
}

NWK_PROTOCOL_VERSIONS = {
    1: "0b0001: Zigbee 2004",
    2: "0b0010: Zigbee PRO",
    3: "0b0011: Zigbee Green Power",
}

NWK_DR_STATES = {
    0: "0b00: Suppress route discovery",
    1: "0b01: Enable route discovery",
}

NWK_MULTICAST_STATES = {
    False: "0b0: NWK Multicast Disabled",
    True: "0b1: NWK Multicast Enabled",
}

NWK_SECURITY_STATES = {
    False: "0b0: NWK Security Disabled",
    True: "0b1: NWK Security Enabled",
}

NWK_SR_STATES = {
    False: "0b0: NWK Source Route Omitted",
    True: "0b1: NWK Source Route Included",
}

NWK_ED_STATES = {
    False: "0b0: NWK Extended Destination Omitted",
    True: "0b1: NWK Extended Destination Included",
}

NWK_ES_STATES = {
    False: "0b0: NWK Extended Source Omitted",
    True: "0b1: NWK Extended Source Included",
}

NWK_EDI_STATES = {
    False: "0b0: NWK Not End Device Initiator",
    True: "0b1: NWK End Device Initiator",
}

NWK_SECURITY_LEVELS = {
    0: "0b000: None",
    1: "0b001: MIC-32",
    2: "0b010: MIC-64",
    3: "0b011: MIC-128",
    4: "0b100: ENC",
    5: "0b101: ENC-MIC-32",
    6: "0b110: ENC-MIC-64",
    7: "0b111: ENC-MIC-128",
}

NWK_KEY_TYPES = {
    0: "0b00: Data Key",
    1: "0b01: Network Key",
    2: "0b10: Key-Transport Key",
    3: "0b11: Key-Load Key",
}

NWK_EN_STATES = {
    0: "0b0: The source address is not present",
    1: "0b1: The source address is present",
}

NWK_COMMANDS = {
    1: "0x01: NWK Route Request",
    2: "0x02: NWK Route Reply",
    3: "0x03: NWK Network Status",
    4: "0x04: NWK Leave",
    5: "0x05: NWK Route Record",
    6: "0x06: NWK Rejoin Request",
    7: "0x07: NWK Rejoin Response",
    8: "0x08: NWK Link Status",
    9: "0x09: NWK Network Report",
    10: "0x0a: NWK Network Update",
    11: "0x0b: NWK End Device Timeout Request",
    12: "0x0c: NWK End Device Timeout Response",
}

MTO_STATES = {
    0: "0b00: Not a Many-to-One Route Request",
    1: "0b01: Many-to-One Route Request with Route Record support",
    2: "0b10: Many-to-One Route Request without Route Record support",
}

ED_STATES = {
    0: "0b0: The extended destination address is not present",
    1: "0b1: The extended destination address is present",
}

MD_STATES = {
    0: "0b0: The destination address is not a Group ID",
    1: "0b1: The destination address is a Group ID",
}

EO_STATES = {
    0: "0b0: The extended originator address is not present",
    1: "0b1: The extended originator address is present",
}

ER_STATES = {
    0: "0b0: The extended responder address is not present",
    1: "0b1: The extended responder address is present",
}

MR_STATES = {
    0: "0b0: The responder address is not a Group ID",
    1: "0b1: The responder address is a Group ID",
}

STATUS_CODES = {
    0: "0x00: No route available",
    1: "0x01: Tree link failure",
    2: "0x02: Non-tree link failure",
    3: "0x03: Low battery level",
    4: "0x04: No routing capacity",
    5: "0x05: No indirect capacity",
    6: "0x06: Indirect transaction expiry",
    7: "0x07: Target device unavailable",
    8: "0x08: Target address unallocated",
    9: "0x09: Parent link failure",
    10: "0x0a: Validate route",
    11: "0x0b: Source route failure",
    12: "0x0c: Many-to-one route failure",
    13: "0x0d: Address conflict",
    14: "0x0e: Verify addresses",
    15: "0x0f: PAN identifier update",
    16: "0x10: Network address update",
    17: "0x11: Bad frame counter",
    18: "0x12: Bad key sequence number",
}

REJOIN_STATES = {
    0: "0b0: The device will not rejoin the network",
    1: "0b1: The device will rejoin the network",
}

REQUEST_STATES = {
    0: "0b0: The sending device wants to leave the network",
    1: "0b1: Another device wants to leave the network",
}

RC_STATES = {
    0: "0b0: The device's children will not be removed from the network",
    1: "0b1: The device's children will be removed from the network",
}

APC_STATES = {
    0: "0b0: The sender is not capable of becoming a PAN coordinator",
    1: "0b1: The sender is capable of becoming a PAN coordinator",
}

DEVICE_TYPES = {
    0: "0b0: Zigbee End Device",
    1: "0b1: Zigbee Router",
}

POWER_SOURCES = {
    0: "0b0: The sender is not a mains-powered device",
    1: "0b1: The sender is a mains-powered device",
}

RXIDLE_STATES = {
    0: "0b0: Disables the receiver to conserve power when idle",
    1: "0b1: Does not disable the receiver to conserve power",
}

SECURITY_CAPABILITIES = {
    0: "0b0: Cannot transmit and receive secure MAC frames",
    1: "0b1: Can transmit and receive secure MAC frames",
}

ALLOCADDR_STATES = {
    0: "0b0: Does not request a short address",
    1: "0b1: Requests a short address",
}

REJOIN_STATUSES = {
    0: "0x00: Rejoin successful",
    1: "0x01: PAN at capacity",
    2: "0x02: PAN access denied",
}

FIRST_FRAME_STATUSES = {
    0: "0b0: This is not the first frame of the sender's link status",
    1: "0b1: This is the first frame of the sender's link status",
}

LAST_FRAME_STATUSES = {
    0: "0b0: This is not the last frame of the sender's link status",
    1: "0b1: This is the last frame of the sender's link status",
}

REPORT_TYPES = {
    0: "0b000: PAN Identifier Conflict",
}

UPDATE_TYPES = {
    0: "0b000: PAN Identifier Update",
}

RT_VALUES = {
    0: "0x00: 10 seconds",
    1: "0x01: 2 minutes",
    2: "0x02: 4 minutes",
    3: "0x03: 8 minutes",
    4: "0x04: 16 minutes",
    5: "0x05: 32 minutes",
    6: "0x06: 64 minutes",
    7: "0x07: 128 minutes",
    8: "0x08: 256 minutes",
    9: "0x09: 512 minutes",
    10: "0x0a: 1024 minutes",
    11: "0x0b: 2048 minutes",
    12: "0x0c: 4096 minutes",
    13: "0x0d: 8192 minutes",
    14: "0x0e: 16384 minutes",
}

RT_STATUSES = {
    0: "0x00: Success",
    1: "0x01: Incorrect Value",
}

POLL_STATES = {
    0: "0b0: MAC Data Poll Keepalive is not supported",
    1: "0b1: MAC Data Poll Keepalive is supported",
}

TIMEOUT_STATES = {
    0: "0b0: End Device Timeout Request Keepalive is not supported",
    1: "0b1: End Device Timeout Request Keepalive is supported",
}

ROUTER_CAPACITIES = {
    0: "0b0: The sender cannot accept join requests from routers",
    1: "0b1: The sender can accept join requests from routers",
}

END_DEVICE_CAPACITIES = {
    0: "0b0: The sender cannot accept join requests from end devices",
    1: "0b1: The sender can accept join requests from end devices",
}


def nwk_fields(pkt, msg_queue):
    """Parse Zigbee NWK fields."""
    if config.entry["mac_frametype"].startswith("0b000:"):
        nwk_beacon(pkt)
        return
    elif not config.entry["mac_frametype"].startswith("0b001:"):
        msg_obj = "Packet #{} in {} contains unknown NWK fields".format(
            config.entry["pkt_num"],
            config.entry["pcap_filename"],
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.entry["error_msg"] = "PE301: Unknown NWK fields"
        return

    # Frame Control field (2 bytes)
    # Frame Type subfield (2 bits)
    if not (
        config.set_entry(
            "nwk_frametype",
            pkt[ZigbeeNWK].frametype,
            NWK_FRAME_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE302: Unknown NWK frame type"
        return
    # Protocol Version subfield (4 bits)
    if not (
        config.set_entry(
            "nwk_protocolversion",
            pkt[ZigbeeNWK].proto_version,
            NWK_PROTOCOL_VERSIONS,
        )
    ):
        config.entry["error_msg"] = "PE303: Unknown NWK protocol version"
        return
    # Discover Route subfield (2 bits)
    if not (
        config.set_entry(
            "nwk_discroute",
            pkt[ZigbeeNWK].discover_route,
            NWK_DR_STATES,
        )
    ):
        config.entry["error_msg"] = "PE304: Unknown NWK DR state"
        return
    # Multicast subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_multicast",
            pkt[ZigbeeNWK].flags.multicast,
            NWK_MULTICAST_STATES,
        )
    ):
        config.entry["error_msg"] = "PE305: Unknown NWK multicast state"
        return
    # Security subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_security",
            pkt[ZigbeeNWK].flags.security,
            NWK_SECURITY_STATES,
        )
    ):
        config.entry["error_msg"] = "PE306: Unknown NWK security state"
        return
    # Source Route subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_srcroute",
            pkt[ZigbeeNWK].flags.source_route,
            NWK_SR_STATES,
        )
    ):
        config.entry["error_msg"] = "PE307: Unknown NWK SR state"
        return
    # Extended Destination subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_extendeddst",
            pkt[ZigbeeNWK].flags.extended_dst,
            NWK_ED_STATES,
        )
    ):
        config.entry["error_msg"] = "PE308: Unknown NWK ED state"
        return
    # Extended Source subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_extendedsrc",
            pkt[ZigbeeNWK].flags.extended_src,
            NWK_ES_STATES,
        )
    ):
        config.entry["error_msg"] = "PE309: Unknown NWK ES state"
        return
    # End Device Initiator subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_edinitiator",
            pkt[ZigbeeNWK].flags.reserved1,
            NWK_EDI_STATES,
        )
    ):
        config.entry["error_msg"] = "PE310: Unknown NWK EDI state"
        return

    # Destination Short Address field (2 bytes)
    config.entry["nwk_dstshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWK].destination,
    )

    # Source Short Address field (2 bytes)
    config.entry["nwk_srcshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWK].source,
    )

    # Radius field (1 byte)
    config.entry["nwk_radius"] = pkt[ZigbeeNWK].radius

    # Sequence Number field (1 byte)
    config.entry["nwk_seqnum"] = pkt[ZigbeeNWK].seqnum

    # Destination Extended Address field (0/8 bytes)
    if config.entry["nwk_extendeddst"].startswith("0b1:"):
        config.entry["nwk_dstextendedaddr"] = format(
            pkt[ZigbeeNWK].ext_dst,
            "016x",
        )
    elif not config.entry["nwk_extendeddst"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid NWK ED state"
        return

    # Source Extended Address field (0/8 bytes)
    if config.entry["nwk_extendedsrc"].startswith("0b1:"):
        config.entry["nwk_srcextendedaddr"] = format(
            pkt[ZigbeeNWK].ext_src,
            "016x",
        )
    elif not config.entry["nwk_extendedsrc"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid NWK ES state"
        return

    # Multicast Control field (0/1 byte)
    if config.entry["nwk_multicast"].startswith("0b1:"):
        msg_obj = (
            "Packet #{} ".format(config.entry["pkt_num"])
            + "in {} ".format(config.entry["pcap_filename"])
            + "contains a Multicast Control field "
            + "which could not be processed"
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.entry["error_msg"] = "Could not process the Multicast Control"
        return
    elif not config.entry["nwk_multicast"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid Multicast state"
        return

    # Source Route Subframe field (variable)
    if config.entry["nwk_srcroute"].startswith("0b1:"):
        config.entry["nwk_srcroute_relaycount"] = pkt[ZigbeeNWK].relay_count
        config.entry["nwk_srcroute_relayindex"] = pkt[ZigbeeNWK].relay_index
        if config.entry["nwk_srcroute_relaycount"] > 0:
            config.entry["nwk_srcroute_relaylist"] = ",".join(
                ["0x{:04x}".format(addr) for addr in pkt[ZigbeeNWK].relays],
            )
    elif not config.entry["nwk_srcroute"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid NWK SR state"
        return

    if config.entry["nwk_security"].startswith("0b1:"):
        # NWK Auxiliary Header field (6/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            nwk_auxiliary(pkt, msg_queue)
        else:
            config.entry["error_msg"] = (
                "The NWK Auxiliary Header is not included"
            )
            return
    elif config.entry["nwk_security"].startswith("0b0:"):
        # NWK Payload field (variable)
        if config.entry["nwk_frametype"].startswith("0b00:"):
            if pkt.haslayer(ZigbeeAppDataPayload):
                aps_fields(pkt, msg_queue)
            else:
                config.entry["error_msg"] = "There are no Zigbee APS fields"
                return
        elif config.entry["nwk_frametype"].startswith("0b01:"):
            if pkt.haslayer(ZigbeeNWKCommandPayload):
                nwk_command(pkt, msg_queue)
            else:
                config.entry["error_msg"] = "There are no NWK Command fields"
                return
        elif config.entry["nwk_frametype"].startswith("0b11:"):
            msg_obj = (
                "Packet #{} ".format(config.entry["pkt_num"])
                + "in {} ".format(config.entry["pcap_filename"])
                + "contains Inter-PAN fields which were ignored"
            )
            if msg_queue is None:
                logging.debug(msg_obj)
            else:
                msg_queue.put((Message.DEBUG, msg_obj))
            config.entry["error_msg"] = "Ignored the Inter-PAN fields"
            return
        else:
            config.entry["error_msg"] = "Invalid NWK frame type"
            return
    else:
        config.entry["error_msg"] = "Invalid NWK security state"
        return


def nwk_beacon(pkt):
    # Beacon Payload field (15 bytes)
    # Protocol ID subfield (8 bits)
    config.entry["nwk_beacon_protocolid"] = pkt[ZigBeeBeacon].proto_id
    # Stack Profile subfield (4 bits)
    config.entry["nwk_beacon_stackprofile"] = pkt[ZigBeeBeacon].stack_profile
    # Protocol Version subfield (4 bits)
    if not (
        config.set_entry(
            "nwk_beacon_protocolversion",
            pkt[ZigBeeBeacon].nwkc_protocol_version,
            NWK_PROTOCOL_VERSIONS,
        )
    ):
        config.entry["error_msg"] = "PE340: Unknown NWK protocol version"
        return
    # Router Capacity subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_beacon_routercap",
            pkt[ZigBeeBeacon].router_capacity,
            ROUTER_CAPACITIES,
        )
    ):
        config.entry["error_msg"] = "PE341: Unknown router capacity"
        return
    # Device Depth subfield (4 bits)
    config.entry["nwk_beacon_devdepth"] = pkt[ZigBeeBeacon].device_depth
    # End Device Capacity subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_beacon_edcap",
            pkt[ZigBeeBeacon].end_device_capacity,
            END_DEVICE_CAPACITIES,
        )
    ):
        config.entry["error_msg"] = "PE342: Unknown end device capacity"
        return
    # Extended PAN ID subfield (64 bits)
    config.entry["nwk_beacon_epid"] = format(
        pkt[ZigBeeBeacon].extended_pan_id,
        "016x",
    )
    # TX Offset subfield (24 bits)
    config.entry["nwk_beacon_txoffset"] = pkt[ZigBeeBeacon].tx_offset
    # Update ID subfield (8 bits)
    config.entry["nwk_beacon_updateid"] = pkt[ZigBeeBeacon].update_id

    # Beacons do not contain any other fields
    if len(bytes(pkt[ZigBeeBeacon].payload)) != 0:
        config.entry["error_msg"] = "PE355: Unexpected payload"
        return


def nwk_auxiliary(pkt, msg_queue):
    # Security Control field (1 byte)
    # Security Level subfield (3 bits)
    if not (
        config.set_entry(
            "nwk_aux_seclevel",
            pkt[ZigbeeSecurityHeader].nwk_seclevel,
            NWK_SECURITY_LEVELS,
        )
    ):
        config.entry["error_msg"] = "PE311: Unknown NWK security level"
        return
    # Key Identifier subfield (2 bits)
    if not (
        config.set_entry(
            "nwk_aux_keytype",
            pkt[ZigbeeSecurityHeader].key_type,
            NWK_KEY_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE312: Unknown NWK key type"
        return
    # Extended Nonce subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_aux_extnonce",
            pkt[ZigbeeSecurityHeader].extended_nonce,
            NWK_EN_STATES,
        )
    ):
        config.entry["error_msg"] = "PE313: Unknown NWK EN state"
        return

    # Frame Counter field (4 bytes)
    config.entry["nwk_aux_framecounter"] = pkt[ZigbeeSecurityHeader].fc
    frame_counter = pkt[ZigbeeSecurityHeader].fc

    # Source Address field (0/8 bytes)
    if config.entry["nwk_aux_extnonce"].startswith("0b1:"):
        config.entry["nwk_aux_srcaddr"] = format(
            pkt[ZigbeeSecurityHeader].source,
            "016x",
        )
        potential_sources = {
            pkt[ZigbeeSecurityHeader].source,
        }
    elif config.entry["nwk_aux_extnonce"].startswith("0b0:"):
        panid = config.entry["mac_dstpanid"]
        shortaddr = config.entry["mac_srcshortaddr"]
        potential_sources = config.get_alternative_addresses(panid, shortaddr)

        if len(potential_sources) == 0:
            potential_sources = {
                int(extendedaddr, 16)
                for extendedaddr in config.extended_addresses.keys()
            }

        if config.entry["nwk_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["nwk_srcextendedaddr"], 16),
            )
        if config.entry["mac_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["mac_srcextendedaddr"], 16),
            )
    else:
        config.entry["error_msg"] = "Invalid NWK EN state"
        return

    # Key Sequence Number field (1 byte)
    if config.entry["nwk_aux_keytype"].startswith("0b01:"):
        config.entry["nwk_aux_keyseqnum"] = (
            pkt[ZigbeeSecurityHeader].key_seqnum
        )
        key_seqnum = pkt[ZigbeeSecurityHeader].key_seqnum
        potential_keys = config.network_keys.values()
    else:
        config.entry["error_msg"] = "Unexpected key type on the NWK layer"
        return

    # Attempt to decrypt the payload
    nwk_header = pkt[ZigbeeNWK].copy()
    nwk_header.remove_payload()
    header = bytes(nwk_header)
    sec_control = bytes(pkt[ZigbeeSecurityHeader])[0]
    enc_payload = pkt[ZigbeeSecurityHeader].data[:-4]
    mic = pkt[ZigbeeSecurityHeader].data[-4:]
    for source_addr in potential_sources:
        for key in potential_keys:
            dec_payload, auth_payload = crypto.zigbee_dec_ver(
                key,
                source_addr,
                frame_counter,
                sec_control,
                header,
                key_seqnum,
                enc_payload,
                mic,
            )

            # Check whether the decrypted payload is authentic
            if auth_payload:
                config.entry["nwk_aux_deckey"] = key.hex()
                config.entry["nwk_aux_decsrc"] = format(source_addr, "016x")
                config.entry["nwk_aux_decpayload"] = dec_payload.hex()

                # NWK Payload field (variable)
                if config.entry["nwk_frametype"].startswith("0b00:"):
                    dec_pkt = ZigbeeAppDataPayload(dec_payload)
                    config.entry["nwk_aux_decshow"] = dec_pkt.show(dump=True)
                    aps_fields(dec_pkt, msg_queue)
                    return
                elif config.entry["nwk_frametype"].startswith("0b01:"):
                    dec_pkt = ZigbeeNWKCommandPayload(dec_payload)
                    config.entry["nwk_aux_decshow"] = dec_pkt.show(dump=True)
                    nwk_command(dec_pkt, msg_queue)
                    return
                else:
                    config.entry["error_msg"] = (
                        "Unexpected format of the decrypted NWK payload"
                    )
                    return
    msg_obj = (
        "Unable to decrypt with a {} ".format(config.entry["nwk_aux_keytype"])
        + "the NWK payload of packet #{} ".format(config.entry["pkt_num"])
        + "in {}".format(config.entry["pcap_filename"])
    )
    if msg_queue is None:
        logging.debug(msg_obj)
    else:
        msg_queue.put((Message.DEBUG, msg_obj))
    config.entry["warning_msg"] = "PW301: Unable to decrypt the NWK payload"


def nwk_command(pkt, msg_queue):
    # Command Identifier field (1 byte)
    if not (
        config.set_entry(
            "nwk_cmd_id",
            pkt[ZigbeeNWKCommandPayload].cmd_identifier,
            NWK_COMMANDS,
        )
    ):
        config.entry["error_msg"] = "PE314: Unknown NWK command"
        return

    # Compute the NWK Command Payload Length
    # The constant 14 was derived by summing the following:
    #  2: MAC Frame Control
    #  1: MAC Sequence Number
    #  2: NWK Frame Control
    #  2: NWK Destination Short Address
    #  2: NWK Source Short Address
    #  1: NWK Radius
    #  1: NWK Sequence Number
    #  1: NWK Command Identifier
    #  2: MAC Frame Check Sequence
    config.entry["nwk_cmd_payloadlength"] = config.entry["phy_length"] - 14
    # Compute the length of the MAC Destination Addressing fields
    if config.entry["mac_dstaddrmode"].startswith("0b10:"):
        config.entry["nwk_cmd_payloadlength"] -= 4
    elif config.entry["mac_dstaddrmode"].startswith("0b11:"):
        config.entry["nwk_cmd_payloadlength"] -= 10
    elif not config.entry["mac_dstaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = "Invalid MAC DA mode"
        return
    # Compute the length of the MAC Source Addressing fields
    if config.entry["mac_srcaddrmode"].startswith("0b10:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            config.entry["nwk_cmd_payloadlength"] -= 2
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        config.entry["nwk_cmd_payloadlength"] -= 2
    elif config.entry["mac_srcaddrmode"].startswith("0b11:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            config.entry["nwk_cmd_payloadlength"] -= 2
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        config.entry["nwk_cmd_payloadlength"] -= 8
    elif not config.entry["mac_srcaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = "Invalid MAC SA mode"
        return
    # Compute the length of the MAC Auxiliary Security Header field
    if config.entry["mac_security"].startswith("0b1:"):
        msg_obj = (
            "Ignored packet #{} ".format(config.entry["pkt_num"])
            + "in {} ".format(config.entry["pcap_filename"])
            + "because it utilizes security services on the MAC layer"
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.entry["error_msg"] = (
            "Ignored NWK command with enabled MAC-layer security"
        )
        return
    elif not config.entry["mac_security"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid MAC security state"
        return
    # Check for the presence of the Destination Extended Address field
    if config.entry["nwk_extendeddst"].startswith("0b1:"):
        config.entry["nwk_cmd_payloadlength"] -= 8
    elif not config.entry["nwk_extendeddst"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid NWK ED state"
        return
    # Check for the presence of the Source Extended Address field
    if config.entry["nwk_extendedsrc"].startswith("0b1:"):
        config.entry["nwk_cmd_payloadlength"] -= 8
    elif not config.entry["nwk_extendedsrc"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid NWK ES state"
        return
    # Check for the presence of the Multicast Control field
    if config.entry["nwk_multicast"].startswith("0b1:"):
        msg_obj = (
            "Ignored packet #{} ".format(config.entry["pkt_num"])
            + "in {} ".format(config.entry["pcap_filename"])
            + "because it contains a Multicast Control field"
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.entry["error_msg"] = (
            "Ignored NWK command that includes the Multicast Control field"
        )
        return
    elif not config.entry["nwk_multicast"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid Multicast state"
        return
    # Check for the presence of the Source Route Subframe field
    if config.entry["nwk_srcroute"].startswith("0b1:"):
        config.entry["nwk_cmd_payloadlength"] -= (
            2 + 2*config.entry["nwk_srcroute_relaycount"]
        )
    elif not config.entry["nwk_srcroute"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid NWK SR state"
        return
    # Compute the length of the NWK Auxiliary Header field
    if config.entry["nwk_security"].startswith("0b1:"):
        config.entry["nwk_cmd_payloadlength"] -= 9
        if config.entry["nwk_aux_extnonce"].startswith("0b1:"):
            config.entry["nwk_cmd_payloadlength"] -= 8
        elif not config.entry["nwk_aux_extnonce"].startswith("0b0:"):
            config.entry["error_msg"] = "Invalid NWK EN state"
            return
        if config.entry["nwk_aux_keytype"].startswith("0b01:"):
            config.entry["nwk_cmd_payloadlength"] -= 1
        else:
            config.entry["error_msg"] = "Unexpected key type on the NWK layer"
            return
    elif not config.entry["nwk_security"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid NWK security state"
        return

    # Command Payload field (variable)
    if config.entry["nwk_cmd_id"].startswith("0x01:"):
        nwk_routerequest(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x02:"):
        nwk_routereply(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x03:"):
        nwk_networkstatus(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x04:"):
        nwk_leave(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x05:"):
        nwk_routerecord(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x06:"):
        nwk_rejoinreq(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x07:"):
        nwk_rejoinrsp(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x08:"):
        nwk_linkstatus(pkt, msg_queue)
    elif config.entry["nwk_cmd_id"].startswith("0x09:"):
        nwk_networkreport(pkt, msg_queue)
    elif config.entry["nwk_cmd_id"].startswith("0x0a:"):
        nwk_networkupdate(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x0b:"):
        nwk_edtimeoutreq(pkt)
    elif config.entry["nwk_cmd_id"].startswith("0x0c:"):
        nwk_edtimeoutrsp(pkt)
    else:
        config.entry["error_msg"] = "Invalid NWK command"
        return


def nwk_routerequest(pkt):
    # Command Options field (1 byte)
    # Many-to-One subfield (2 bits)
    if not (
        config.set_entry(
            "nwk_routerequest_mto",
            pkt[ZigbeeNWKCommandPayload].many_to_one,
            MTO_STATES,
        )
    ):
        config.entry["error_msg"] = "PE315: Unknown MTO state"
        return
    # Extended Destination subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_routerequest_ed",
            pkt[ZigbeeNWKCommandPayload].dest_addr_bit,
            ED_STATES,
        )
    ):
        config.entry["error_msg"] = "PE316: Unknown ED state"
        return
    # Multicast subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_routerequest_mc",
            pkt[ZigbeeNWKCommandPayload].multicast,
            MD_STATES,
        )
    ):
        config.entry["error_msg"] = "PE317: Unknown MD state"
        return

    # Route Request Identifier field (1 byte)
    config.entry["nwk_routerequest_id"] = (
        pkt[ZigbeeNWKCommandPayload].route_request_identifier
    )

    # Destination Short Address field (2 bytes)
    config.entry["nwk_routerequest_dstshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].destination_address,
    )

    # Path Cost field (1 byte)
    config.entry["nwk_routerequest_pathcost"] = (
        pkt[ZigbeeNWKCommandPayload].path_cost
    )

    # Destination Extended Address field (0/8 bytes)
    if config.entry["nwk_routerequest_ed"].startswith("0b1:"):
        config.entry["nwk_routerequest_dstextendedaddr"] = format(
            pkt[ZigbeeNWKCommandPayload].ext_dst,
            "016x",
        )
    elif not config.entry["nwk_routerequest_ed"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid ED state"
        return

    # NWK Route Request commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE343: Unexpected payload"
        return


def nwk_routereply(pkt):
    # Command Options field (1 byte)
    # Extended Originator subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_routereply_eo",
            pkt[ZigbeeNWKCommandPayload].originator_addr_bit,
            EO_STATES,
        )
    ):
        config.entry["error_msg"] = "PE318: Unknown EO state"
        return
    # Extended Responder subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_routereply_er",
            pkt[ZigbeeNWKCommandPayload].responder_addr_bit,
            ER_STATES,
        )
    ):
        config.entry["error_msg"] = "PE319: Unknown ER state"
        return
    # Multicast subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_routereply_mc",
            pkt[ZigbeeNWKCommandPayload].multicast,
            MR_STATES,
        )
    ):
        config.entry["error_msg"] = "PE320: Unknown MR state"
        return

    # Route Request Identifier field (1 byte)
    config.entry["nwk_routereply_id"] = (
        pkt[ZigbeeNWKCommandPayload].route_request_identifier
    )

    # Originator Short Address field (2 bytes)
    config.entry["nwk_routereply_origshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].originator_address,
    )

    # Responder Short Address field (2 bytes)
    config.entry["nwk_routereply_respshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].responder_address,
    )

    # Path Cost field (1 byte)
    config.entry["nwk_routereply_pathcost"] = (
        pkt[ZigbeeNWKCommandPayload].path_cost
    )

    # Originator Extended Address field (0/8 bytes)
    if config.entry["nwk_routereply_eo"].startswith("0b1:"):
        config.entry["nwk_routereply_origextendedaddr"] = format(
            pkt[ZigbeeNWKCommandPayload].originator_addr,
            "016x",
        )
    elif not config.entry["nwk_routereply_eo"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid EO state"
        return

    # Responder Extended Address field (0/8 bytes)
    if config.entry["nwk_routereply_er"].startswith("0b1:"):
        config.entry["nwk_routereply_respextendedaddr"] = format(
            pkt[ZigbeeNWKCommandPayload].responder_addr,
            "016x",
        )
    elif not config.entry["nwk_routereply_er"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid ER state"
        return

    # NWK Route Reply commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE344: Unexpected payload"
        return


def nwk_networkstatus(pkt):
    # Status Code field (1 byte)
    if not (
        config.set_entry(
            "nwk_networkstatus_code",
            pkt[ZigbeeNWKCommandPayload].status_code,
            STATUS_CODES,
        )
    ):
        config.entry["error_msg"] = "PE321: Unknown status code"
        return

    # Destination Short Address field (2 bytes)
    config.entry["nwk_networkstatus_dstshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].destination_address,
    )

    # NWK Network Status commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE345: Unexpected payload"
        return


def nwk_leave(pkt):
    # Command Options field (1 byte)
    # Rejoin subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_leave_rejoin",
            pkt[ZigbeeNWKCommandPayload].rejoin,
            REJOIN_STATES,
        )
    ):
        config.entry["error_msg"] = "PE322: Unknown rejoin state"
        return
    # Request subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_leave_request",
            pkt[ZigbeeNWKCommandPayload].request,
            REQUEST_STATES,
        )
    ):
        config.entry["error_msg"] = "PE323: Unknown request state"
        return
    # Remove Children subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_leave_rmch",
            pkt[ZigbeeNWKCommandPayload].remove_children,
            RC_STATES,
        )
    ):
        config.entry["error_msg"] = "PE324: Unknown RC state"
        return

    # NWK Leave commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE346: Unexpected payload"
        return


def nwk_routerecord(pkt):
    # Relay Count field (1 byte)
    config.entry["nwk_routerecord_relaycount"] = (
        pkt[ZigbeeNWKCommandPayload].rr_relay_count
    )

    # Relay List field (variable)
    if config.entry["nwk_routerecord_relaycount"] > 0:
        config.entry["nwk_routerecord_relaylist"] = ",".join(
            [
                "0x{:04x}".format(addr)
                for addr in pkt[ZigbeeNWKCommandPayload].rr_relay_list
            ],
        )

    # NWK Route Record commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE347: Unexpected payload"
        return


def nwk_rejoinreq(pkt):
    # Capability Information field (1 byte)
    # Alternate PAN Coordinator subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_rejoinreq_apc",
            pkt[ZigbeeNWKCommandPayload].alternate_pan_coordinator,
            APC_STATES,
        )
    ):
        config.entry["error_msg"] = "PE325: Unknown APC state"
        return
    # Device Type subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_rejoinreq_devtype",
            pkt[ZigbeeNWKCommandPayload].device_type,
            DEVICE_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE326: Unknown device type"
        return
    # Power Source subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_rejoinreq_powsrc",
            pkt[ZigbeeNWKCommandPayload].power_source,
            POWER_SOURCES,
        )
    ):
        config.entry["error_msg"] = "PE327: Unknown power source"
        return
    # Receiver On When Idle subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_rejoinreq_rxidle",
            pkt[ZigbeeNWKCommandPayload].receiver_on_when_idle,
            RXIDLE_STATES,
        )
    ):
        config.entry["error_msg"] = "PE328: Unknown RX state when idle"
        return
    # Security Capability subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_rejoinreq_seccap",
            pkt[ZigbeeNWKCommandPayload].security_capability,
            SECURITY_CAPABILITIES,
        )
    ):
        config.entry["error_msg"] = "PE329: Unknown MAC security capability"
        return
    # Allocate Address subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_rejoinreq_allocaddr",
            pkt[ZigbeeNWKCommandPayload].allocate_address,
            ALLOCADDR_STATES,
        )
    ):
        config.entry["error_msg"] = "PE330: Unknown address allocation"
        return

    # NWK Rejoin Request commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE348: Unexpected payload"
        return


def nwk_rejoinrsp(pkt):
    # Network Address field (2 bytes)
    config.entry["nwk_rejoinrsp_shortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].network_address,
    )

    # Rejoin Status field (1 byte)
    if not (
        config.set_entry(
            "nwk_rejoinrsp_status",
            pkt[ZigbeeNWKCommandPayload].rejoin_status,
            REJOIN_STATUSES,
        )
    ):
        config.entry["error_msg"] = "PE331: Unknown rejoin status"
        return

    # NWK Rejoin Response commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE349: Unexpected payload"
        return


def nwk_linkstatus(pkt, msg_queue):
    # Command Options field (1 byte)
    # Entry Count subfield (5 bits)
    config.entry["nwk_linkstatus_count"] = (
        pkt[ZigbeeNWKCommandPayload].entry_count
    )
    # First Frame subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_linkstatus_first",
            pkt[ZigbeeNWKCommandPayload].first_frame,
            FIRST_FRAME_STATUSES,
        )
    ):
        config.entry["error_msg"] = "PE332: Unknown first frame status"
        return
    # Last Frame subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_linkstatus_last",
            pkt[ZigbeeNWKCommandPayload].last_frame,
            LAST_FRAME_STATUSES,
        )
    ):
        config.entry["error_msg"] = "PE333: Unknown last frame status"
        return

    # Link Status List field (variable)
    linkstatus_list = pkt[ZigbeeNWKCommandPayload].link_status_list
    if config.entry["nwk_linkstatus_count"] != len(linkstatus_list):
        msg_obj = (
            "Packet #{} ".format(config.entry["pkt_num"])
            + "in {} ".format(config.entry["pcap_filename"])
            + "contains {} ".format(config.entry["nwk_linkstatus_count"])
            + "link status entries but read only "
            + "{} link status entries".format(len(linkstatus_list))
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.entry["error_msg"] = "Unable to process the Link Status List"
        return
    if config.entry["nwk_linkstatus_count"] > 0:
        config.entry["nwk_linkstatus_addresses"] = ",".join(
            [
                "0x{:04x}".format(link.neighbor_network_address)
                for link in linkstatus_list
            ],
        )
        config.entry["nwk_linkstatus_incomingcosts"] = ",".join(
            [str(link.incoming_cost) for link in linkstatus_list],
        )
        config.entry["nwk_linkstatus_outgoingcosts"] = ",".join(
            [str(link.outgoing_cost) for link in linkstatus_list],
        )

    # NWK Link Status commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE350: Unexpected payload"
        return


def nwk_networkreport(pkt, msg_queue):
    # Command Options field (1 byte)
    # Report Information Count subfield (5 bits)
    config.entry["nwk_networkreport_count"] = (
        pkt[ZigbeeNWKCommandPayload].report_information_count
    )
    # Report Command Identifier subfield (3 bits)
    if not (
        config.set_entry(
            "nwk_networkreport_type",
            pkt[ZigbeeNWKCommandPayload].report_command_identifier,
            REPORT_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE334: Unknown report type"
        return

    # EPID field (8 bytes)
    config.entry["nwk_networkreport_epid"] = format(
        pkt[ZigbeeNWKCommandPayload].epid,
        "016x",
    )

    # Report Information field (variable)
    if config.entry["nwk_networkreport_type"].startswith("0b000:"):
        # PAN ID List subfield (variable)
        panid_list = pkt[ZigbeeNWKCommandPayload].PAN_ID_conflict_report
        if config.entry["nwk_networkreport_count"] != len(panid_list):
            msg_obj = (
                "Packet #{} ".format(config.entry["pkt_num"])
                + "in {} ".format(config.entry["pcap_filename"])
                + "contains {} ".format(config.entry["nwk_network_count"])
                + "but read only PAN identifiers "
                + "{} PAN identifiers".format(len(panid_list))
            )
            if msg_queue is None:
                logging.debug(msg_obj)
            else:
                msg_queue.put((Message.DEBUG, msg_obj))
            config.entry["error_msg"] = "Unable to process the PAN IDs"
            return
        if config.entry["nwk_networkreport_count"] > 0:
            config.entry["nwk_networkreport_info"] = ",".join(
                ["0x{:04x}".format(panid) for panid in panid_list],
            )
    else:
        config.entry["error_msg"] = "Invalid report type"
        return

    # NWK Network Report commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE351: Unexpected payload"
        return


def nwk_networkupdate(pkt):
    # Command Options field (1 byte)
    # Update Information Count subfield (5 bits)
    config.entry["nwk_networkupdate_count"] = (
        pkt[ZigbeeNWKCommandPayload].update_information_count
    )
    # Update Command Identifier subfield (3 bits)
    if not (
        config.set_entry(
            "nwk_networkupdate_type",
            pkt[ZigbeeNWKCommandPayload].update_command_identifier,
            UPDATE_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE335: Unknown update type"
        return

    # EPID field (8 bytes)
    config.entry["nwk_networkupdate_epid"] = format(
        pkt[ZigbeeNWKCommandPayload].epid,
        "016x",
    )

    # Update ID field (1 byte)
    config.entry["nwk_networkupdate_updateid"] = (
        pkt[ZigbeeNWKCommandPayload].update_id
    )

    # Update Information field (variable)
    if config.entry["nwk_networkupdate_type"].startswith("0b000:"):
        # New PAN ID subfield (2 bytes)
        config.entry["nwk_networkupdate_newpanid"] = "0x{:04x}".format(
            pkt[ZigbeeNWKCommandPayload].new_PAN_ID,
        )
    else:
        config.entry["error_msg"] = "Invalid update type"
        return

    # NWK Network Update commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE352: Unexpected payload"
        return


def nwk_edtimeoutreq(pkt):
    # Requested Timeout field (1 byte)
    if not (
        config.set_entry(
            "nwk_edtimeoutreq_reqtime",
            pkt[ZigbeeNWKCommandPayload].req_timeout,
            RT_VALUES,
        )
    ):
        config.entry["error_msg"] = "PE336: Unknown RT value"
        return

    # End Device Configuration field (1 byte)
    config.entry["nwk_edtimeoutreq_edconf"] = (
        pkt[ZigbeeNWKCommandPayload].ed_conf
    )

    # NWK End Device Timeout Request commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE353: Unexpected payload"
        return


def nwk_edtimeoutrsp(pkt):
    # Status field (1 byte)
    if not (
        config.set_entry(
            "nwk_edtimeoutrsp_status",
            pkt[ZigbeeNWKCommandPayload].status,
            RT_STATUSES,
        )
    ):
        config.entry["error_msg"] = "PE337: Unknown RT status"
        return

    # Parent Information field (1 byte)
    # MAC Data Poll Keepalive subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_edtimeoutrsp_poll",
            pkt[ZigbeeNWKCommandPayload].mac_data_poll_keepalive,
            POLL_STATES,
        )
    ):
        config.entry["error_msg"] = "PE338: Unknown poll state"
        return
    # End Device Timeout Request Keepalive subfield (1 bit)
    if not (
        config.set_entry(
            "nwk_edtimeoutrsp_timeout",
            pkt[ZigbeeNWKCommandPayload].ed_timeout_req_keepalive,
            TIMEOUT_STATES,
        )
    ):
        config.entry["error_msg"] = "PE339: Unknown timeout state"
        return

    # NWK End Device Timeout Response commands do not contain any other fields
    if len(bytes(pkt[ZigbeeNWKCommandPayload].payload)) != 0:
        config.entry["error_msg"] = "PE354: Unexpected payload"
        return
