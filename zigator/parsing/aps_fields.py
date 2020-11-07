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

import os

from scapy.all import ZigbeeAppCommandPayload
from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigbeeClusterLibrary
from scapy.all import ZigbeeDeviceProfile
from scapy.all import ZigbeeSecurityHeader

from .. import config
from .. import crypto
from .aps_getters import get_aps_aux_extnonce
from .aps_getters import get_aps_aux_keytype
from .aps_getters import get_aps_aux_seclevel
from .aps_getters import get_aps_clustername
from .aps_getters import get_aps_command
from .aps_getters import get_aps_confirmkey_status
from .aps_getters import get_aps_delmode
from .aps_getters import get_aps_fragmentation
from .aps_getters import get_aps_frametype
from .aps_getters import get_aps_initflag
from .aps_getters import get_aps_profilename
from .aps_getters import get_aps_reqkeytype
from .aps_getters import get_aps_stdkeytype
from .aps_getters import get_aps_updatedevice_status
from .aps_getters import get_zcl_clustername
from .aps_getters import get_zdp_clustername
from .zcl_fields import zcl_fields
from .zdp_fields import zdp_fields


def aps_transportkey(pkt, msg_queue):
    # Standard Key Type field (1 byte)
    config.entry["aps_transportkey_stdkeytype"] = get_aps_stdkeytype(pkt)

    # Key Descriptor field (25/32/33 bytes)
    if (config.entry["aps_transportkey_stdkeytype"]
            == "Standard Network Key"):
        # Key field (16 bytes)
        config.entry["aps_transportkey_key"] = (
            pkt[ZigbeeAppCommandPayload].key.hex()
        )

        # Key Sequence Number field (1 byte)
        config.entry["aps_transportkey_keyseqnum"] = (
            pkt[ZigbeeAppCommandPayload].key_seqnum
        )

        # Destination Extended Address field (8 bytes)
        config.entry["aps_transportkey_dstextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].dest_addr, "016x")

        # Source Extended Address field (8 bytes)
        config.entry["aps_transportkey_srcextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].src_addr, "016x")

        # Store the sniffed network key
        key_bytes = pkt[ZigbeeAppCommandPayload].key
        key_type = "network"
        key_name = "_sniffed_{}_{}".format(
            os.path.join(
                config.entry["pcap_directory"],
                config.entry["pcap_filename"]),
            config.entry["pkt_num"])
        warning_msg = config.add_sniffed_key(key_bytes, key_type, key_name)
        if warning_msg is not None:
            msg_queue.put((config.WARNING_MSG, warning_msg))

        return
    elif (config.entry["aps_transportkey_stdkeytype"]
            == "Trust Center Link Key"):
        # Key field (16 bytes)
        config.entry["aps_transportkey_key"] = (
            pkt[ZigbeeAppCommandPayload].key.hex()
        )

        # Destination Extended Address field (8 bytes)
        config.entry["aps_transportkey_dstextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].dest_addr, "016x")

        # Source Extended Address field (8 bytes)
        config.entry["aps_transportkey_srcextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].src_addr, "016x")

        # Store the sniffed link key
        key_bytes = pkt[ZigbeeAppCommandPayload].key
        key_type = "link"
        key_name = "_sniffed_{}_{}".format(
            os.path.join(
                config.entry["pcap_directory"],
                config.entry["pcap_filename"]),
            config.entry["pkt_num"])
        warning_msg = config.add_sniffed_key(key_bytes, key_type, key_name)
        if warning_msg is not None:
            msg_queue.put((config.WARNING_MSG, warning_msg))

        return
    elif (config.entry["aps_transportkey_stdkeytype"]
            == "Application Link Key"):
        # Key field (16 bytes)
        config.entry["aps_transportkey_key"] = (
            pkt[ZigbeeAppCommandPayload].key.hex()
        )

        # Partner Extended Address field (8 bytes)
        config.entry["aps_transportkey_prtextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].partner_addr, "016x")

        # Initiator Flag field (1 byte)
        config.entry["aps_transportkey_initflag"] = get_aps_initflag(pkt)

        # Store the sniffed link key
        key_bytes = pkt[ZigbeeAppCommandPayload].key
        key_type = "link"
        key_name = "_sniffed_{}_{}".format(
            os.path.join(
                config.entry["pcap_directory"],
                config.entry["pcap_filename"]),
            config.entry["pkt_num"])
        warning_msg = config.add_sniffed_key(key_bytes, key_type, key_name)
        if warning_msg is not None:
            msg_queue.put((config.WARNING_MSG, warning_msg))

        return
    else:
        config.entry["error_msg"] = "Unknown Standard Key Type"
        return


def aps_updatedevice(pkt):
    # Device Extended Address field (8 bytes)
    config.entry["aps_updatedevice_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address, "016x")

    # Device Short Address field (2 bytes)
    config.entry["aps_updatedevice_shortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeAppCommandPayload].short_address)

    # Status field (1 byte)
    config.entry["aps_updatedevice_status"] = get_aps_updatedevice_status(pkt)

    return


def aps_removedevice(pkt):
    # Target Extended Address field (8 bytes)
    config.entry["aps_removedevice_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address, "016x")

    return


def aps_requestkey(pkt):
    # Request Key Type field (1 byte)
    config.entry["aps_requestkey_reqkeytype"] = get_aps_reqkeytype(pkt)

    if (config.entry["aps_requestkey_reqkeytype"]
            == "Application Link Key"):
        # Partner Extended Address field (8 bytes)
        config.entry["aps_requestkey_prtextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].partner_addr, "016x")

        return
    elif (config.entry["aps_requestkey_reqkeytype"]
            == "Trust Center Link Key"):
        # The Partner Extended Address field is not included
        return
    else:
        config.entry["error_msg"] = "Unknown Request Key Type value"
        return


def aps_switchkey(pkt):
    # Key Sequence Number field (1 byte)
    config.entry["aps_switchkey_keyseqnum"] = (
        pkt[ZigbeeAppCommandPayload].seqnum
    )

    return


def aps_tunnel(pkt, msg_queue):
    # Destination Extended Address field (8 bytes)
    config.entry["aps_tunnel_dstextendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].dest_addr, "016x")

    # Tunneled Frame Control field (1 byte)
    if pkt[ZigbeeAppCommandPayload].aps_frametype == 1:
        config.entry["aps_tunnel_frametype"] = "APS Command"
    else:
        config.entry["error_msg"] = "Unexpected tunneled frame type"
        return
    if pkt[ZigbeeAppCommandPayload].delivery_mode == 0:
        config.entry["aps_tunnel_delmode"] = "Normal unicast delivery"
    else:
        config.entry["error_msg"] = "Unexpected tunneled delivery mode"
        return
    if pkt[ZigbeeAppCommandPayload].frame_control.ack_format:
        config.entry["error_msg"] = "Unexpected tunneled ACK format"
        return
    else:
        config.entry["aps_tunnel_ackformat"] = "APS ACK Format Disabled"
    if pkt[ZigbeeAppCommandPayload].frame_control.security:
        config.entry["aps_tunnel_security"] = "APS Security Enabled"
    else:
        config.entry["error_msg"] = "Unexpected tunneled security state"
        return
    if pkt[ZigbeeAppCommandPayload].frame_control.ack_req:
        config.entry["aps_tunnel_ackreq"] = (
            "The sender requests an APS ACK"
        )
    else:
        config.entry["aps_tunnel_ackreq"] = (
            "The sender does not request an APS ACK"
        )
    if pkt[ZigbeeAppCommandPayload].frame_control.extended_hdr:
        config.entry["error_msg"] = (
            "Unexpected tunneled extended header state"
        )
        return
    else:
        config.entry["aps_tunnel_exthdr"] = (
            "The extended header is not included"
        )

    # Tunneled APS Counter field (1 byte)
    config.entry["aps_tunnel_counter"] = pkt[ZigbeeAppCommandPayload].counter

    # Tunneled Auxiliary Header field (13 bytes)
    if config.entry["aps_security"] == "APS Security Enabled":
        config.entry["error_msg"] = (
            "An APS Auxiliary Header was already processed"
        )
        return
    elif config.entry["aps_security"] == "APS Security Disabled":
        aps_auxiliary(pkt, msg_queue)
        return
    else:
        config.entry["error_msg"] = "Unknown APS security state"
        return

    return


def aps_verifykey(pkt):
    # Standard Key Type field (1 byte)
    config.entry["aps_verifykey_stdkeytype"] = get_aps_stdkeytype(pkt)

    # Source Extended Address field (8 bytes)
    config.entry["aps_verifykey_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address, "016x")

    # Initiator Verify-Key Hash Value field (16 bytes)
    config.entry["aps_verifykey_keyhash"] = (
        pkt[ZigbeeAppCommandPayload].key_hash.hex()
    )

    return


def aps_confirmkey(pkt):
    # Status field (1 byte)
    config.entry["aps_confirmkey_status"] = get_aps_confirmkey_status(pkt)

    # Standard Key Type field (1 byte)
    config.entry["aps_confirmkey_stdkeytype"] = get_aps_stdkeytype(pkt)

    # Destination Extended Address field (8 bytes)
    config.entry["aps_confirmkey_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address, "016x")

    return


def aps_command_payload(pkt, msg_queue):
    # Command Identifier field (1 byte)
    config.entry["aps_cmd_id"] = get_aps_command(pkt)

    # Command Payload field (variable)
    if config.entry["aps_cmd_id"] == "APS Transport Key":
        aps_transportkey(pkt, msg_queue)
        return
    elif config.entry["aps_cmd_id"] == "APS Update Device":
        aps_updatedevice(pkt)
        return
    elif config.entry["aps_cmd_id"] == "APS Remove Device":
        aps_removedevice(pkt)
        return
    elif config.entry["aps_cmd_id"] == "APS Request Key":
        aps_requestkey(pkt)
        return
    elif config.entry["aps_cmd_id"] == "APS Switch Key":
        aps_switchkey(pkt)
        return
    elif config.entry["aps_cmd_id"] == "APS Tunnel":
        aps_tunnel(pkt, msg_queue)
        return
    elif config.entry["aps_cmd_id"] == "APS Verify Key":
        aps_verifykey(pkt)
        return
    elif config.entry["aps_cmd_id"] == "APS Confirm Key":
        aps_confirmkey(pkt)
        return
    return


def aps_auxiliary(pkt, msg_queue):
    # Security Control field (1 byte)
    config.entry["aps_aux_seclevel"] = get_aps_aux_seclevel(pkt)
    config.entry["aps_aux_keytype"] = get_aps_aux_keytype(pkt)
    config.entry["aps_aux_extnonce"] = get_aps_aux_extnonce(pkt)

    # Frame Counter field (4 bytes)
    config.entry["aps_aux_framecounter"] = pkt[ZigbeeSecurityHeader].fc
    frame_counter = pkt[ZigbeeSecurityHeader].fc

    # Source Address field (0/8 bytes)
    if (config.entry["aps_aux_extnonce"]
            == "The source address is present"):
        config.entry["aps_aux_srcaddr"] = format(
            pkt[ZigbeeSecurityHeader].source, "016x")
        potential_sources = set([pkt[ZigbeeSecurityHeader].source])
    elif (config.entry["aps_aux_extnonce"]
            == "The source address is not present"):
        potential_sources = set()
        shortaddr = config.entry["nwk_srcshortaddr"]
        panid = config.entry["mac_dstpanid"]

        if (shortaddr, panid) in config.addresses:
            if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                potential_sources.add(
                    int(config.addresses[(shortaddr, panid)], 16))
            else:
                potential_sources.update(
                    [int(extendedaddr, 16)
                     for extendedaddr in config.devices.keys()])
        else:
            potential_sources.update(
                [int(extendedaddr, 16)
                 for extendedaddr in config.devices.keys()])

        if config.entry["nwk_aux_srcaddr"] is not None:
            potential_sources.add(
                int(config.entry["nwk_aux_srcaddr"], 16))
        if config.entry["nwk_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["nwk_srcextendedaddr"], 16))
        if config.entry["mac_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["mac_srcextendedaddr"], 16))
    else:
        config.entry["error_msg"] = "Unknown APS EN state"
        return

    # Key Sequence Number field (0/1 byte)
    if config.entry["aps_aux_keytype"] == "Network Key":
        config.entry["aps_aux_keyseqnum"] = (
            pkt[ZigbeeSecurityHeader].key_seqnum
        )
        key_seqnum = pkt[ZigbeeSecurityHeader].key_seqnum
        potential_keys = config.network_keys.values()
    elif config.entry["aps_aux_keytype"] == "Data Key":
        key_seqnum = None
        potential_keys = config.link_keys.values()
    elif config.entry["aps_aux_keytype"] == "Key-Transport Key":
        key_seqnum = None
        potential_keys = set([crypto.zigbee_hmac(bytes.fromhex("00"), key)
                              for key in config.link_keys.values()])
    elif config.entry["aps_aux_keytype"] == "Key-Load Key":
        key_seqnum = None
        potential_keys = set([crypto.zigbee_hmac(bytes.fromhex("02"), key)
                              for key in config.link_keys.values()])
    else:
        config.entry["error_msg"] = "Unknown APS key type"
        return

    # Attempt to decrypt the payload
    if config.entry["aps_cmd_id"] == "APS Tunnel":
        tunneled_framecontrol = (
                pkt[ZigbeeAppCommandPayload].aps_frametype
                + 4*pkt[ZigbeeAppCommandPayload].delivery_mode
        )
        if pkt[ZigbeeAppCommandPayload].frame_control.ack_format:
            tunneled_framecontrol += 16
        if pkt[ZigbeeAppCommandPayload].frame_control.security:
            tunneled_framecontrol += 32
        if pkt[ZigbeeAppCommandPayload].frame_control.ack_req:
            tunneled_framecontrol += 64
        if pkt[ZigbeeAppCommandPayload].frame_control.extended_hdr:
            tunneled_framecontrol += 128
        tunneled_counter = pkt[ZigbeeAppCommandPayload].counter
        header = bytearray([tunneled_framecontrol, tunneled_counter])
    else:
        aps_header = pkt[ZigbeeAppDataPayload].copy()
        aps_header.remove_payload()
        header = bytes(aps_header)
    sec_control = bytes(pkt[ZigbeeSecurityHeader])[0]
    enc_payload = pkt[ZigbeeSecurityHeader].data[:-4]
    mic = pkt[ZigbeeSecurityHeader].data[-4:]
    for source_addr in potential_sources:
        for key in potential_keys:
            dec_payload, auth_payload = crypto.zigbee_dec_ver(
                key, source_addr, frame_counter, sec_control,
                header, key_seqnum, enc_payload, mic)

            # Check whether the decrypted payload is authentic
            if auth_payload:
                config.entry["aps_aux_deckey"] = key.hex()
                config.entry["aps_aux_decsrc"] = format(source_addr, "016x")
                config.entry["aps_aux_decpayload"] = dec_payload.hex()

                # APS Payload field (variable)
                if config.entry["aps_frametype"] == "APS Data":
                    if (config.entry["aps_profilename"]
                            == "Zigbee Device Profile (ZDP)"):
                        dec_pkt = ZigbeeDeviceProfile(dec_payload)
                        config.entry["aps_aux_decshow"] = (
                            dec_pkt.show(dump=True)
                        )
                        zdp_fields(dec_pkt)
                        return
                    elif (config.entry["aps_profilename"].split()[0]
                            != "Unknown"):
                        dec_pkt = ZigbeeClusterLibrary(dec_payload)
                        config.entry["aps_aux_decshow"] = (
                            dec_pkt.show(dump=True)
                        )
                        zcl_fields(dec_pkt)
                        return
                    else:
                        config.entry["error_msg"] = (
                            "Unknown APS profile with ID {}"
                            "".format(config.entry["aps_profileid"])
                        )
                        return
                elif config.entry["aps_frametype"] == "APS Command":
                    dec_pkt = ZigbeeAppCommandPayload(dec_payload)
                    config.entry["aps_aux_decshow"] = (
                        dec_pkt.show(dump=True)
                    )
                    aps_command_payload(dec_pkt, msg_queue)
                    return
                elif config.entry["aps_frametype"] == "APS Acknowledgment":
                    # APS Acknowledgments do not contain any other fields
                    return
                else:
                    config.entry["error_msg"] = (
                        "Unexpected format of the decrypted APS payload"
                    )
                    return

    msg_queue.put(
        (config.DEBUG_MSG,
         "Unable to decrypt with a {} the APS payload of packet #{} in {}"
         "".format(config.entry["aps_aux_keytype"],
                   config.entry["pkt_num"],
                   config.entry["pcap_filename"])))
    config.entry["warning_msg"] = "PW401: Unable to decrypt the APS payload"
    return


def aps_data_header(pkt, msg_queue):
    if (config.entry["aps_delmode"] == "Normal unicast delivery"
            or config.entry["aps_delmode"] == "Broadcast"):
        # Destination Endpoint field (1 byte)
        config.entry["aps_dstendpoint"] = (
            pkt[ZigbeeAppDataPayload].dst_endpoint
        )
    elif config.entry["aps_delmode"] == "Group addressing":
        # Group Address field (2 bytes)
        config.entry["aps_groupaddr"] = "0x{:04x}".format(
            pkt[ZigbeeAppDataPayload].group_addr)
    else:
        config.entry["error_msg"] = "Unknown APS delivery mode"
        return

    # Cluster Identifier field (2 bytes)
    config.entry["aps_clusterid"] = "0x{:04x}".format(
        pkt[ZigbeeAppDataPayload].cluster)
    config.entry["aps_clustername"] = get_aps_clustername(pkt)

    # Profile Identifier field (2 bytes)
    config.entry["aps_profileid"] = "0x{:04x}".format(
        pkt[ZigbeeAppDataPayload].profile)
    config.entry["aps_profilename"] = get_aps_profilename(pkt)

    # Source Endpoint field (1 byte)
    config.entry["aps_srcendpoint"] = pkt[ZigbeeAppDataPayload].src_endpoint

    # APS Counter field (1 byte)
    config.entry["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    # Extended Header field (0/1/2 bytes)
    if config.entry["aps_exthdr"] == "The extended header is included":
        # Extended Frame Control field (1 byte)
        config.entry["aps_fragmentation"] = get_aps_fragmentation(pkt)

        # Block Number field (0/1 byte)
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
        # APS Auxiliary Header field (5/6/13/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            aps_auxiliary(pkt, msg_queue)
            return
        else:
            config.entry["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.entry["aps_security"] == "APS Security Disabled":
        # APS Data fields (variable)
        if config.entry["aps_profilename"] == "Zigbee Device Profile (ZDP)":
            if pkt.haslayer(ZigbeeDeviceProfile):
                zdp_fields(pkt)
                return
            else:
                config.entry["error_msg"] = "There are no ZDP fields"
                return
        elif config.entry["aps_profilename"].split()[0] != "Unknown":
            if pkt.haslayer(ZigbeeClusterLibrary):
                zcl_fields(pkt)
                return
            else:
                config.entry["error_msg"] = "There are no ZCL fields"
                return
        else:
            config.entry["error_msg"] = (
                "Unknown APS profile with ID {}"
                "".format(config.entry["aps_profileid"])
            )
            return
    else:
        config.entry["error_msg"] = "Unknown APS security state"
        return


def aps_command_header(pkt, msg_queue):
    # APS Counter field (1 byte)
    config.entry["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    if config.entry["aps_security"] == "APS Security Enabled":
        # APS Auxiliary Header field (5/6/13/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            aps_auxiliary(pkt, msg_queue)
            return
        else:
            config.entry["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.entry["aps_security"] == "APS Security Disabled":
        # APS Command fields (variable)
        if pkt.haslayer(ZigbeeAppCommandPayload):
            aps_command_payload(pkt, msg_queue)
            return
        else:
            config.entry["error_msg"] = "There are no APS Command fields"
            return
    else:
        config.entry["error_msg"] = "Unknown APS security state"
        return


def aps_ack_header(pkt, msg_queue):
    if config.entry["aps_ackformat"] == "APS ACK Format Disabled":
        # Destination Endpoint field (1 byte)
        config.entry["aps_dstendpoint"] = (
            pkt[ZigbeeAppDataPayload].dst_endpoint
        )

        # Cluster Identifier field (2 bytes)
        config.entry["aps_clusterid"] = "0x{:04x}".format(
            pkt[ZigbeeAppDataPayload].cluster)
        config.entry["aps_clustername"] = get_aps_clustername(pkt)

        # Profile Identifier field (2 bytes)
        config.entry["aps_profileid"] = "0x{:04x}".format(
            pkt[ZigbeeAppDataPayload].profile)
        config.entry["aps_profilename"] = get_aps_profilename(pkt)

        # Source Endpoint field (1 byte)
        config.entry["aps_srcendpoint"] = (
            pkt[ZigbeeAppDataPayload].src_endpoint
        )
    elif config.entry["aps_ackformat"] != "APS ACK Format Enabled":
        config.entry["error_msg"] = "Unknown ACK Format state"
        return

    # APS Counter field (1 byte)
    config.entry["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    # Extended Header field (0/1/3 bytes)
    if config.entry["aps_exthdr"] == "The extended header is included":
        # Extended Frame Control field (1 byte)
        config.entry["aps_fragmentation"] = get_aps_fragmentation(pkt)

        # Block Number field (0/1 byte)
        if (config.entry["aps_fragmentation"] == "First fragment"
                or config.entry["aps_fragmentation"] == "Continued fragment"):
            config.entry["aps_blocknumber"] = (
                pkt[ZigbeeAppDataPayload].block_number
            )

            # ACK Bitfield (1 byte)
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
        # APS Auxiliary Header field (5/6/13/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            aps_auxiliary(pkt, msg_queue)
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


def aps_fields(pkt, msg_queue):
    """Parse Zigbee APS fields."""
    # Frame Control field (1 byte)
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

    # The APS Header fields vary significantly between different frame types
    if config.entry["aps_frametype"] == "APS Data":
        aps_data_header(pkt, msg_queue)
    elif config.entry["aps_frametype"] == "APS Command":
        aps_command_header(pkt, msg_queue)
    elif config.entry["aps_frametype"] == "APS Acknowledgment":
        aps_ack_header(pkt, msg_queue)
    elif config.entry["aps_frametype"] == "APS Inter-PAN":
        msg_queue.put(
            (config.DEBUG_MSG,
             "Packet #{} in {} contains Inter-PAN fields"
             "which were ignored"
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"])))
        config.entry["error_msg"] = "Ignored the Inter-PAN fields"
        return
    else:
        config.entry["error_msg"] = "Unknown APS frame type"
