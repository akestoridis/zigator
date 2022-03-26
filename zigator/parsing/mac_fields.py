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
import struct

from scapy.all import (
    Dot15d4,
    Dot15d4AuxSecurityHeader,
    Dot15d4Beacon,
    Dot15d4Cmd,
    Dot15d4CmdAssocReq,
    Dot15d4CmdAssocResp,
    Dot15d4CmdCoordRealign,
    Dot15d4CmdCoordRealignPage,
    Dot15d4CmdDisassociation,
    Dot15d4CmdGTSReq,
    Dot15d4Data,
    Dot15d4FCS,
    ThreadBeacon,
    ZigBeeBeacon,
    ZigbeeNWK,
)

from .. import (
    config,
    crypto,
)
from ..enums import (
    Message,
    Protocol,
)
from .nwk_fields import nwk_fields
from .thr_fields import thr_fields


MAC_FRAME_TYPES = {
    0: "0b000: MAC Beacon",
    1: "0b001: MAC Data",
    2: "0b010: MAC Acknowledgment",
    3: "0b011: MAC Command",
}

MAC_SECURITY_STATES = {
    0: "0b0: MAC Security Disabled",
    1: "0b1: MAC Security Enabled",
}

MAC_FP_STATES = {
    0: "0b0: No additional packets are pending for the receiver",
    1: "0b1: Additional packets are pending for the receiver",
}

MAC_AR_STATES = {
    0: "0b0: The sender does not request a MAC Acknowledgment",
    1: "0b1: The sender requests a MAC Acknowledgment",
}

MAC_PIC_STATES = {
    0: "0b0: Do not compress the source PAN ID",
    1: "0b1: The source PAN ID is the same as the destination PAN ID",
}

MAC_DA_MODES = {
    0: "0b00: No destination MAC address",
    2: "0b10: Short destination MAC address",
    3: "0b11: Extended destination MAC address",
}

MAC_FRAME_VERSIONS = {
    0: "0b00: IEEE 802.15.4-2003 Frame Version",
    1: "0b01: IEEE 802.15.4-2006 Frame Version",
    2: "0b10: IEEE 802.15.4-2015 Frame Version",
}

MAC_SA_MODES = {
    0: "0b00: No source MAC address",
    2: "0b10: Short source MAC address",
    3: "0b11: Extended source MAC address",
}

MAC_SECURITY_LEVELS = {
    0: "0b000: None",
    1: "0b001: MIC-32",
    2: "0b010: MIC-64",
    3: "0b011: MIC-128",
    4: "0b100: ENC",
    5: "0b101: ENC-MIC-32",
    6: "0b110: ENC-MIC-64",
    7: "0b111: ENC-MIC-128",
}

MAC_KEY_ID_MODES = {
    0: "0b00: Implicit key determination",
    1: "0b01: Explicit key determination with the 8-byte default key source",
    2: "0b10: Explicit key determination with the 4-byte Key Source subfield",
    3: "0b11: Explicit key determination with the 8-byte Key Source subfield",
}

MAC_COMMANDS = {
    1: "0x01: MAC Association Request",
    2: "0x02: MAC Association Response",
    3: "0x03: MAC Disassociation Notification",
    4: "0x04: MAC Data Request",
    5: "0x05: MAC PAN ID Conflict Notification",
    6: "0x06: MAC Orphan Notification",
    7: "0x07: MAC Beacon Request",
    8: "0x08: MAC Coordinator Realignment",
    9: "0x09: MAC GTS Request",
}

APC_STATES = {
    0: "0b0: The sender is not capable of becoming a PAN coordinator",
    1: "0b1: The sender is capable of becoming a PAN coordinator",
}

DEVICE_TYPES = {
    0: "0b0: Reduced-Function Device",
    1: "0b1: Full-Function Device",
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

ASSOC_STATUSES = {
    0: "0x00: Association successful",
    1: "0x01: PAN at capacity",
    2: "0x02: PAN access denied",
}

DISASSOC_REASONS = {
    1: "0x01: The coordinator wishes the device to leave the PAN",
    2: "0x02: The device wishes to leave the PAN",
}

GTS_DIRECTIONS = {
    0: "0b0: Transmit-Only GTS",
    1: "0b1: Receive-Only GTS",
}

GTS_CHARACTERISTICS_TYPES = {
    0: "0b0: GTS Deallocation",
    1: "0b1: GTS Allocation",
}

PANCOORDINATOR_STATES = {
    0: "0b0: The sender is not the PAN coordinator",
    1: "0b1: The sender is the PAN coordinator",
}

ASSOCPERMIT_STATES = {
    0: "0b0: The sender is currently not accepting association requests",
    1: "0b1: The sender is currently accepting association requests",
}


def mac_fields(pkt, msg_queue):
    """Parse IEEE 802.15.4 MAC fields."""
    config.row["mac_show"] = pkt.show(dump=True)
    if pkt[Dot15d4FCS].fcs is None:
        config.row["error_msg"] = (
            "PE201: The frame check sequence (FCS) field is not included"
        )
        return

    comp_fcs = struct.unpack("<H", pkt.compute_fcs(bytes(pkt)[:-2]))[0]
    if pkt[Dot15d4FCS].fcs != comp_fcs:
        msg_obj = (
            "The received FCS (0x{:04x}), ".format(pkt[Dot15d4FCS].fcs)
            + "for packet #{} ".format(config.row["pkt_num"])
            + "in {}, ".format(config.row["pcap_filename"])
            + "does not match the computed FCS (0x{:04x})".format(comp_fcs)
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.row["error_msg"] = (
            "PE202: Incorrect frame check sequence (FCS)"
        )
        return

    # Frame Check Sequence field (2 bytes)
    config.row["mac_fcs"] = "0x{:04x}".format(pkt[Dot15d4FCS].fcs)

    # Frame Control field (2 bytes)
    # Frame Type subfield (3 bits)
    if not (
        config.update_row(
            "mac_frametype",
            pkt[Dot15d4FCS].fcf_frametype,
            MAC_FRAME_TYPES,
            "PE203: Unknown MAC frame type",
        )
    ):
        return
    # Security subfield (1 bit)
    if not (
        config.update_row(
            "mac_security",
            pkt[Dot15d4FCS].fcf_security,
            MAC_SECURITY_STATES,
            "PE204: Unknown MAC security state",
        )
    ):
        return
    # Frame Pending subfield (1 bit)
    if not (
        config.update_row(
            "mac_framepending",
            pkt[Dot15d4FCS].fcf_pending,
            MAC_FP_STATES,
            "PE205: Unknown MAC FP state",
        )
    ):
        return
    # Acknowledgment Request subfield (1 bit)
    if not (
        config.update_row(
            "mac_ackreq",
            pkt[Dot15d4FCS].fcf_ackreq,
            MAC_AR_STATES,
            "PE206: Unknown MAC AR state",
        )
    ):
        return
    # PAN ID Compression subfield (1 bit)
    if not (
        config.update_row(
            "mac_panidcomp",
            pkt[Dot15d4FCS].fcf_panidcompress,
            MAC_PIC_STATES,
            "PE207: Unknown MAC PIC state",
        )
    ):
        return
    # Destination Addressing Mode subfield (2 bits)
    if not (
        config.update_row(
            "mac_dstaddrmode",
            pkt[Dot15d4FCS].fcf_destaddrmode,
            MAC_DA_MODES,
            "PE208: Unknown MAC DA mode",
        )
    ):
        return
    # Frame Version subfield (2 bits)
    if not (
        config.update_row(
            "mac_frameversion",
            pkt[Dot15d4FCS].fcf_framever,
            MAC_FRAME_VERSIONS,
            "PE209: Unknown MAC frame version",
        )
    ):
        return
    # Source Addressing Mode subfield (2 bits)
    if not (
        config.update_row(
            "mac_srcaddrmode",
            pkt[Dot15d4FCS].fcf_srcaddrmode,
            MAC_SA_MODES,
            "PE210: Unknown MAC SA mode",
        )
    ):
        return

    # Sequence Number field (1 byte)
    config.row["mac_seqnum"] = pkt[Dot15d4FCS].seqnum

    # Addressing fields (variable)
    if config.row["mac_frametype"].startswith("0b010:"):
        # MAC Acknowledgments do not contain any other fields
        if len(bytes(pkt[Dot15d4FCS].payload)) != 0:
            config.row["error_msg"] = "PE224: Unexpected payload"
            return
    elif config.row["mac_frametype"].startswith("0b001:"):
        if pkt.haslayer(Dot15d4Data):
            mac_data_header(pkt, msg_queue)
        else:
            config.row["error_msg"] = "There are no MAC Data fields"
            return
    elif config.row["mac_frametype"].startswith("0b000:"):
        if pkt.haslayer(Dot15d4Beacon):
            mac_beacon_header_preaux(pkt, msg_queue)
        else:
            config.row["error_msg"] = "There are no MAC Beacon fields"
            return
    elif config.row["mac_frametype"].startswith("0b011:"):
        if pkt.haslayer(Dot15d4Cmd):
            mac_command_header_preaux(pkt, msg_queue)
        else:
            config.row["error_msg"] = "There are no MAC Command fields"
            return
    else:
        config.row["error_msg"] = "Invalid MAC frame type"
        return


def mac_data_header(pkt, msg_queue):
    # Destination Addressing fields (0/4/10 bytes)
    if config.row["mac_dstaddrmode"].startswith("0b10:"):
        # Destination PAN ID subfield (2 bytes)
        config.row["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_panid,
        )
        # Destination Short Address subfield (2 bytes)
        config.row["mac_dstshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_addr,
        )
    elif config.row["mac_dstaddrmode"].startswith("0b11:"):
        # Destination PAN ID subfield (2 bytes)
        config.row["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_panid,
        )
        # Destination Extended Address subfield (8 bytes)
        config.row["mac_dstextendedaddr"] = format(
            pkt[Dot15d4Data].dest_addr,
            "016x",
        )
    elif not config.row["mac_dstaddrmode"].startswith("0b00:"):
        config.row["error_msg"] = "Invalid MAC DA mode"
        return

    # Source Addressing fields (0/2/4/8/10 bytes)
    if config.row["mac_srcaddrmode"].startswith("0b10:"):
        if config.row["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.row["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Data].src_panid,
            )
        elif not config.row["mac_panidcomp"].startswith("0b1:"):
            config.row["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Short Address subfield (2 bytes)
        config.row["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Data].src_addr,
        )
    elif config.row["mac_srcaddrmode"].startswith("0b11:"):
        if config.row["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.row["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Data].src_panid,
            )
        elif not config.row["mac_panidcomp"].startswith("0b1:"):
            config.row["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Extended Address subfield (8 bytes)
        config.row["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Data].src_addr,
            "016x",
        )
    elif not config.row["mac_srcaddrmode"].startswith("0b00:"):
        config.row["error_msg"] = "Invalid MAC SA mode"
        return

    if config.row["mac_security"].startswith("0b1:"):
        if config.nwk_protocol == Protocol.ZIGBEE:
            # Zigbee packets are not expected to utilize security services
            # on the MAC layer
            msg_obj = (
                "The packet #{} ".format(config.row["pkt_num"])
                + "in {} ".format(config.row["pcap_filename"])
                + "is utilizing security services on the MAC layer"
            )
            if msg_queue is None:
                logging.debug(msg_obj)
            else:
                msg_queue.put((Message.DEBUG, msg_obj))
            config.row["error_msg"] = "Ignored secured MAC Data packet"
            return
        elif config.nwk_protocol == Protocol.THREAD:
            if config.row["mac_frameversion"].startswith("0b01:"):
                # Auxiliary Security Header field (5/6/10/14 bytes)
                if pkt.haslayer(Dot15d4AuxSecurityHeader):
                    mac_auxiliary(pkt, msg_queue)
                else:
                    config.row["error_msg"] = (
                        "The MAC Auxiliary Security Header is not included"
                    )
                    return
            else:
                config.row["error_msg"] = (
                    "Could not process the secured MAC Data packet "
                    + " due to the its frame version"
                )
                return
        else:
            raise ValueError(
                "Unsupported networking protocol for parsing purposes: "
                + "{}".format(config.nwk_protocol),
            )
    elif config.row["mac_security"].startswith("0b0:"):
        mac_data_payload(pkt, msg_queue)
    else:
        config.row["error_msg"] = "Invalid MAC security state"
        return


def mac_beacon_header_preaux(pkt, msg_queue):
    if not config.row["mac_panidcomp"].startswith("0b0:"):
        config.row["error_msg"] = (
            "The source PAN ID of MAC Beacons should not be compressed"
        )
        return
    elif not config.row["mac_dstaddrmode"].startswith("0b00:"):
        config.row["error_msg"] = (
            "MAC Beacons should not contain a destination PAN ID and address"
        )
        return

    # Addressing fields (4/10 bytes)
    # Source PAN ID subfield (2 bytes)
    config.row["mac_srcpanid"] = "0x{:04x}".format(
        pkt[Dot15d4Beacon].src_panid,
    )
    if config.row["mac_srcaddrmode"].startswith("0b10:"):
        # Source Short Address subfield (2 bytes)
        config.row["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Beacon].src_addr,
        )
    elif config.row["mac_srcaddrmode"].startswith("0b11:"):
        # Source Extended Address subfield (8 bytes)
        config.row["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Beacon].src_addr,
            "016x",
        )
    elif config.row["mac_srcaddrmode"].startswith("0b00:"):
        config.row["error_msg"] = (
            "MAC Beacons should contain a source PAN ID and address"
        )
        return
    else:
        config.row["error_msg"] = "Invalid MAC SA mode"
        return

    if config.row["mac_security"].startswith("0b1:"):
        if config.nwk_protocol == Protocol.ZIGBEE:
            # Zigbee packets are not expected to utilize security services
            # on the MAC layer
            msg_obj = (
                "The packet #{} ".format(config.row["pkt_num"])
                + "in {} ".format(config.row["pcap_filename"])
                + "is utilizing security services on the MAC layer"
            )
            if msg_queue is None:
                logging.debug(msg_obj)
            else:
                msg_queue.put((Message.DEBUG, msg_obj))
            config.row["error_msg"] = "Ignored secured MAC Beacon packet"
            return
        elif config.nwk_protocol == Protocol.THREAD:
            if config.row["mac_frameversion"].startswith("0b01:"):
                # Auxiliary Security Header field (5/6/10/14 bytes)
                if pkt.haslayer(Dot15d4AuxSecurityHeader):
                    mac_auxiliary(pkt, msg_queue)
                else:
                    config.row["error_msg"] = (
                        "The MAC Auxiliary Security Header is not included"
                    )
                    return
            else:
                config.row["error_msg"] = (
                    "Could not process the secured MAC Beacon packet "
                    + " due to the its frame version"
                )
                return
        else:
            raise ValueError(
                "Unsupported networking protocol for parsing purposes: "
                + "{}".format(config.nwk_protocol),
            )
    elif config.row["mac_security"].startswith("0b0:"):
        mac_beacon_header_postaux(pkt, msg_queue)
        if config.row["error_msg"] is not None:
            return
        mac_beacon_payload(pkt, msg_queue)
    else:
        config.row["error_msg"] = "Invalid MAC security state"
        return


def mac_command_header_preaux(pkt, msg_queue):
    # Destination Addressing fields (0/4/10 bytes)
    if config.row["mac_dstaddrmode"].startswith("0b10:"):
        # Destination PAN ID subfield (2 bytes)
        config.row["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_panid,
        )
        # Destination Short Address subfield (2 bytes)
        config.row["mac_dstshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_addr,
        )
    elif config.row["mac_dstaddrmode"].startswith("0b11:"):
        # Destination PAN ID subfield (2 bytes)
        config.row["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_panid,
        )
        # Destination Extended Address subfield (8 bytes)
        config.row["mac_dstextendedaddr"] = format(
            pkt[Dot15d4Cmd].dest_addr,
            "016x",
        )
    elif not config.row["mac_dstaddrmode"].startswith("0b00:"):
        config.row["error_msg"] = "Invalid MAC DA mode"
        return

    # Source Addressing fields (0/2/4/8/10 bytes)
    if config.row["mac_srcaddrmode"].startswith("0b10:"):
        if config.row["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.row["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Cmd].src_panid,
            )
        elif not config.row["mac_panidcomp"].startswith("0b1:"):
            config.row["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Short Address subfield (2 bytes)
        config.row["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].src_addr,
        )
    elif config.row["mac_srcaddrmode"].startswith("0b11:"):
        if config.row["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.row["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Cmd].src_panid,
            )
        elif not config.row["mac_panidcomp"].startswith("0b1:"):
            config.row["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Extended Address subfield (8 bytes)
        config.row["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Cmd].src_addr,
            "016x",
        )
    elif not config.row["mac_srcaddrmode"].startswith("0b00:"):
        config.row["error_msg"] = "Invalid MAC SA mode"
        return

    if config.row["mac_security"].startswith("0b1:"):
        if config.nwk_protocol == Protocol.ZIGBEE:
            # Zigbee packets are not expected to utilize security services
            # on the MAC layer
            msg_obj = (
                "The packet #{} ".format(config.row["pkt_num"])
                + "in {} ".format(config.row["pcap_filename"])
                + "is utilizing security services on the MAC layer"
            )
            if msg_queue is None:
                logging.debug(msg_obj)
            else:
                msg_queue.put((Message.DEBUG, msg_obj))
            config.row["error_msg"] = "Ignored secured MAC Command packet"
            return
        elif config.nwk_protocol == Protocol.THREAD:
            if config.row["mac_frameversion"].startswith("0b01:"):
                # Auxiliary Security Header field (5/6/10/14 bytes)
                if pkt.haslayer(Dot15d4AuxSecurityHeader):
                    mac_auxiliary(pkt, msg_queue)
                    config.row["mac_cmd_payloadlength"] = len(
                        pkt[Dot15d4Cmd].sec_payload,
                    )
                else:
                    config.row["error_msg"] = (
                        "The MAC Auxiliary Security Header is not included"
                    )
                    return
            else:
                config.row["error_msg"] = (
                    "Could not process the secured MAC Command packet "
                    + " due to the its frame version"
                )
                return
        else:
            raise ValueError(
                "Unsupported networking protocol for parsing purposes: "
                + "{}".format(config.nwk_protocol),
            )
    elif config.row["mac_security"].startswith("0b0:"):
        mac_command_header_postaux(pkt)
        if config.row["error_msg"] is not None:
            return
        config.row["mac_cmd_payloadlength"] = len(pkt[Dot15d4Cmd].payload)
        mac_command_payload(pkt)
    else:
        config.row["error_msg"] = "Invalid MAC security state"
        return


def mac_auxiliary(pkt, msg_queue):
    # Security Control field (1 byte)
    # Security Level subfield (3 bits)
    if not (
        config.update_row(
            "mac_aux_seclevel",
            pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel,
            MAC_SECURITY_LEVELS,
            "Unknown MAC security level",
        )
    ):
        return
    # Key Identifier Mode subfield (2 bits)
    if not (
        config.update_row(
            "mac_aux_keyidmode",
            pkt[Dot15d4AuxSecurityHeader].sec_sc_keyidmode,
            MAC_KEY_ID_MODES,
            "Unknown MAC key identifier mode",
        )
    ):
        return

    # Frame Counter field (4 bytes)
    frame_counter = pkt[Dot15d4AuxSecurityHeader].sec_framecounter
    config.row["mac_aux_framecounter"] = frame_counter

    # Key Identifier field (0/1/5/9 bytes)
    potential_sources = set()
    if config.row["mac_aux_keyidmode"].startswith("0b00:"):
        if config.row["mac_srcextendedaddr"] is not None:
            potential_sources.add(int(config.row["mac_srcextendedaddr"], 16))
        potential_keys = config.mac_keys.values()
    elif config.row["mac_aux_keyidmode"].startswith("0b01:"):
        # Key Index subfield (1 byte)
        config.row["mac_aux_keyindex"] = (
            pkt[Dot15d4AuxSecurityHeader].sec_keyid_keyindex
        )
        config.derive_thread_keys(config.row["mac_aux_keyindex"])
        potential_keys = config.mac_keys.values()
    elif config.row["mac_aux_keyidmode"].startswith("0b10:"):
        # Key Source subfield (4 bytes)
        config.row["mac_aux_keysource"] = format(
            pkt[Dot15d4AuxSecurityHeader].sec_keyid_keysource,
            "08x",
        )
        # Key Index subfield (1 byte)
        config.row["mac_aux_keyindex"] = (
            pkt[Dot15d4AuxSecurityHeader].sec_keyid_keyindex
        )
        config.derive_thread_keys(config.row["mle_aux_keyindex"])
        # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-thread.c#L775-782
        if (
            pkt[Dot15d4AuxSecurityHeader].sec_keyid_keyindex == 0xff
            and (
                pkt[Dot15d4AuxSecurityHeader].sec_keyid_keysource
                == 0xffffffff
            )
        ):
            # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-thread.c#L692-693
            potential_keys = {
                bytes.fromhex("78581686fdb4580fb092546aecbd1566"),
            }
            # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-ieee802154.h#L211
            potential_sources.add(0x3506feb823d48712)
        else:
            potential_keys = config.mac_keys.values()
    elif config.row["mac_aux_keyidmode"].startswith("0b11:"):
        # Key Source subfield (8 bytes)
        config.row["mac_aux_keysource"] = format(
            pkt[Dot15d4AuxSecurityHeader].sec_keyid_keysource,
            "016x",
        )
        potential_sources.add(int(config.row["mac_aux_keysource"], 16))
        # Key Index subfield (1 byte)
        config.row["mac_aux_keyindex"] = (
            pkt[Dot15d4AuxSecurityHeader].sec_keyid_keyindex
        )
        config.derive_thread_keys(config.row["mac_aux_keyindex"])
        potential_keys = config.mac_keys.values()
    else:
        config.row["error_msg"] = "Invalid MAC key identifier mode"
        return

    # Attempt to decrypt the payload
    if len(potential_sources) == 0:
        potential_sources = {
            int(extendedaddr, 16)
            for extendedaddr in config.extended_addresses.keys()
        }
        if config.row["mac_srcextendedaddr"] is not None:
            potential_sources.add(int(config.row["mac_srcextendedaddr"], 16))
    mac_header = pkt[Dot15d4FCS].copy()
    mac_header.remove_payload()
    header = bytes(mac_header)[:-2]
    if pkt.haslayer(Dot15d4Data):
        unenc_data = pkt[Dot15d4Data].copy()
        if pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel in {0, 1, 2, 3}:
            enc_payload = bytes()
        elif pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel in {4, 5, 6, 7}:
            enc_payload = pkt[Dot15d4Data].sec_payload
        else:
            config.row["error_msg"] = "Unexpected MAC security level"
            return
        mic = pkt[Dot15d4Data].mic
        header += bytes(unenc_data)[:-len(enc_payload)-len(mic)]
    elif pkt.haslayer(Dot15d4Beacon):
        mac_beacon_header_postaux(pkt, msg_queue)
        if config.row["error_msg"] is not None:
            return
        unenc_data = pkt[Dot15d4Beacon].copy()
        if pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel in {0, 1, 2, 3}:
            enc_payload = bytes()
        elif pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel in {4, 5, 6, 7}:
            enc_payload = pkt[Dot15d4Beacon].sec_payload
        else:
            config.row["error_msg"] = "Unexpected MAC security level"
            return
        mic = pkt[Dot15d4Beacon].mic
        header += bytes(unenc_data)[:-len(enc_payload)-len(mic)]
    elif pkt.haslayer(Dot15d4Cmd):
        mac_command_header_postaux(pkt)
        if config.row["error_msg"] is not None:
            return
        unenc_data = pkt[Dot15d4Cmd].copy()
        if pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel in {0, 1, 2, 3}:
            enc_payload = bytes()
        elif pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel in {4, 5, 6, 7}:
            enc_payload = pkt[Dot15d4Cmd].sec_payload
        else:
            config.row["error_msg"] = "Unexpected MAC security level"
            return
        mic = pkt[Dot15d4Cmd].mic
        header += bytes(unenc_data)[:-len(enc_payload)-len(mic)]
    else:
        config.row["error_msg"] = "Could not attempt to decrypt the payload"
        return
    for source_addr in potential_sources:
        for key in potential_keys:
            dec_payload, auth_payload = crypto.ieee802154_dec_ver(
                key,
                source_addr,
                frame_counter,
                pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel,
                header,
                enc_payload,
                mic,
            )

            # Make sure that the decrypted payload is authentic whenever a
            # message integrity code is provided, otherwise warn that the
            # decrypted payload could not be verified
            if auth_payload or len(mic) == 0:
                if len(mic) == 0:
                    config.row["warning_msg"] = (
                        "Could not verify the decrypted MAC payload"
                    )

                config.row["mac_aux_deckey"] = key.hex()
                config.row["mac_aux_decsrc"] = format(source_addr, "016x")

                # MAC Payload field (variable)
                if pkt.haslayer(Dot15d4Data):
                    if (
                        pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel
                        in {0, 1, 2, 3}
                    ):
                        dec_payload = pkt[Dot15d4Data].sec_payload
                    elif not (
                        pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel
                        in {4, 5, 6, 7}
                    ):
                        config.row["error_msg"] = (
                            "Unexpected MAC security level"
                        )
                        return
                    config.row["mac_aux_decpayload"] = dec_payload.hex()

                    if config.nwk_protocol == Protocol.ZIGBEE:
                        dec_pkt = ZigbeeNWK(dec_payload)
                    elif config.nwk_protocol == Protocol.THREAD:
                        tmp_pkt = Dot15d4(bytes(pkt[Dot15d4FCS]))
                        tmp_pkt[Dot15d4].fcf_security = False
                        dec_pkt = Dot15d4(bytes(tmp_pkt) + dec_payload)
                    else:
                        raise ValueError(
                            "Unsupported networking protocol for parsing "
                            + "purposes: {}".format(config.nwk_protocol),
                        )
                    config.row["mac_aux_decshow"] = dec_pkt.show(dump=True)
                    mac_data_payload(dec_pkt, msg_queue)
                    return
                elif pkt.haslayer(Dot15d4Beacon):
                    if (
                        pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel
                        in {0, 1, 2, 3}
                    ):
                        dec_payload = pkt[Dot15d4Beacon].sec_payload
                    elif not (
                        pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel
                        in {4, 5, 6, 7}
                    ):
                        config.row["error_msg"] = (
                            "Unexpected MAC security level"
                        )
                        return
                    config.row["mac_aux_decpayload"] = dec_payload.hex()

                    if len(dec_payload) == 0:
                        config.row["error_msg"] = "There is no beacon payload"
                        return

                    if config.nwk_protocol == Protocol.ZIGBEE:
                        # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-zbee-nwk.c#L1507-1509
                        if dec_payload[0] == 0x00:
                            dec_pkt = ZigBeeBeacon(dec_payload)
                        else:
                            config.row["error_msg"] = (
                                "Unexpected payload for a Zigbee beacon"
                            )
                            return
                    elif config.nwk_protocol == Protocol.THREAD:
                        # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-thread.c#L2223-2225
                        if dec_payload[0] == 0x03:
                            dec_pkt = ThreadBeacon(dec_payload)
                        else:
                            config.row["error_msg"] = (
                                "Unexpected payload for a Thread beacon"
                            )
                            return
                    else:
                        raise ValueError(
                            "Unsupported networking protocol for parsing "
                            + "purposes: {}".format(config.nwk_protocol),
                        )
                    config.row["mac_aux_decshow"] = dec_pkt.show(dump=True)
                    mac_beacon_payload(pkt, msg_queue)
                    return
                elif pkt.haslayer(Dot15d4Cmd):
                    if (
                        pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel
                        in {0, 1, 2, 3}
                    ):
                        dec_payload = pkt[Dot15d4Cmd].sec_payload
                    elif not (
                        pkt[Dot15d4AuxSecurityHeader].sec_sc_seclevel
                        in {4, 5, 6, 7}
                    ):
                        config.row["error_msg"] = (
                            "Unexpected MAC security level"
                        )
                        return
                    config.row["mac_aux_decpayload"] = dec_payload.hex()

                    if config.row["mac_cmd_id"].startswith("0x01:"):
                        dec_pkt = Dot15d4CmdAssocReq(dec_payload)
                    elif config.row["mac_cmd_id"].startswith("0x02:"):
                        dec_pkt = Dot15d4CmdAssocResp(dec_payload)
                    elif config.row["mac_cmd_id"].startswith("0x03:"):
                        dec_pkt = Dot15d4CmdDisassociation(dec_payload)
                    elif config.row["mac_cmd_id"].startswith("0x04:"):
                        # MAC Data Request commands
                        # do not contain any other fields
                        if len(dec_payload) != 0:
                            config.row["error_msg"] = (
                                "PE235: Unexpected payload"
                            )
                        return
                    elif config.row["mac_cmd_id"].startswith("0x05:"):
                        # MAC PAN ID Conflict Notification commands
                        # do not contain any other fields
                        if len(dec_payload) != 0:
                            config.row["error_msg"] = (
                                "PE236: Unexpected payload"
                            )
                        return
                    elif config.row["mac_cmd_id"].startswith("0x06:"):
                        # MAC Orphan Notification commands
                        # do not contain any other fields
                        if len(dec_payload) != 0:
                            config.row["error_msg"] = (
                                "PE237: Unexpected payload"
                            )
                        return
                    elif config.row["mac_cmd_id"].startswith("0x07:"):
                        # MAC Beacon Request commands
                        # do not contain any other fields
                        if len(dec_payload) != 0:
                            config.row["error_msg"] = (
                                "PE238: Unexpected payload"
                            )
                        return
                    elif config.row["mac_cmd_id"].startswith("0x08:"):
                        dec_pkt = Dot15d4CmdCoordRealign(dec_payload)
                    elif config.row["mac_cmd_id"].startswith("0x09:"):
                        dec_pkt = Dot15d4CmdGTSReq(dec_payload)
                    else:
                        config.row["error_msg"] = "Invalid MAC command"
                        return
                    config.row["mac_aux_decshow"] = dec_pkt.show(dump=True)
                    mac_command_payload(dec_pkt)
                    return
                else:
                    config.row["error_msg"] = (
                        "Unexpected format of the decrypted MAC payload"
                    )
                    return
    msg_obj = "Unable to decrypt the MAC payload of packet #{} in {}".format(
        config.row["pkt_num"],
        config.row["pcap_filename"],
    )
    if msg_queue is None:
        logging.debug(msg_obj)
    else:
        msg_queue.put((Message.DEBUG, msg_obj))
    config.row["warning_msg"] = "Unable to decrypt the MAC payload"


def mac_beacon_header_postaux(pkt, msg_queue):
    # Superframe Specification field (2 bytes)
    # Beacon Order subfield (4 bits)
    config.row["mac_beacon_beaconorder"] = pkt[Dot15d4Beacon].sf_beaconorder
    # Superframe Order subfield (4 bits)
    config.row["mac_beacon_sforder"] = pkt[Dot15d4Beacon].sf_sforder
    # Final CAP Slot subfield (4 bits)
    config.row["mac_beacon_finalcap"] = pkt[Dot15d4Beacon].sf_finalcapslot
    # Battery Life Extension subfield (1 bit)
    config.row["mac_beacon_ble"] = pkt[Dot15d4Beacon].sf_battlifeextend
    # PAN Coordinator subfield (1 bit)
    if not (
        config.update_row(
            "mac_beacon_pancoord",
            pkt[Dot15d4Beacon].sf_pancoord,
            PANCOORDINATOR_STATES,
            "PE222: Unknown PAN coordinator state",
        )
    ):
        return
    # Association Permit subfield (1 bit)
    if not (
        config.update_row(
            "mac_beacon_assocpermit",
            pkt[Dot15d4Beacon].sf_assocpermit,
            ASSOCPERMIT_STATES,
            "PE223: Unknown association permit state",
        )
    ):
        return

    # GTS Specification field (1 byte)
    # GTS Descriptor Count subfield (3 bits)
    config.row["mac_beacon_gtsnum"] = pkt[Dot15d4Beacon].gts_spec_desccount
    # GTS Permit subfield (1 bit)
    config.row["mac_beacon_gtspermit"] = pkt[Dot15d4Beacon].gts_spec_permit

    # GTS Directions field (0/1 byte)
    if config.row["mac_beacon_gtsnum"] > 0:
        # GTS Directions Mask subfield (7 bits)
        config.row["mac_beacon_gtsmask"] = pkt[Dot15d4Beacon].gts_dir_mask

    # GTS List field (variable)
    if config.row["mac_beacon_gtsnum"] > 0:
        msg_obj = (
            "Packet #{} ".format(config.row["pkt_num"])
            + "in {} ".format(config.row["pcap_filename"])
            + "contains a GTS List field which could not be processed"
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.row["error_msg"] = "Could not process the GTS List"
        return

    # Pending Address Specification field (1 byte)
    # Number of Short Addresses Pending (3 bits)
    config.row["mac_beacon_nsap"] = pkt[Dot15d4Beacon].pa_num_short
    # Number of Extended Addresses Pending (3 bits)
    config.row["mac_beacon_neap"] = pkt[Dot15d4Beacon].pa_num_long

    # Address List field (variable)
    if config.row["mac_beacon_nsap"] > 0:
        config.row["mac_beacon_shortaddresses"] = ",".join(
            [
                "0x{:04x}".format(addr)
                for addr in pkt[Dot15d4Beacon].pa_short_addresses
            ],
        )
    if config.row["mac_beacon_neap"] > 0:
        config.row["mac_beacon_extendedaddresses"] = ",".join(
            [
                format(addr, "016x")
                for addr in pkt[Dot15d4Beacon].pa_long_addresses
            ],
        )


def mac_command_header_postaux(pkt):
    # Command Frame Identifier field (1 byte)
    if not (
        config.update_row(
            "mac_cmd_id",
            pkt[Dot15d4Cmd].cmd_id,
            MAC_COMMANDS,
            "PE211: Unknown MAC command",
        )
    ):
        return


def mac_data_payload(pkt, msg_queue):
    if config.nwk_protocol == Protocol.ZIGBEE:
        if pkt.haslayer(ZigbeeNWK):
            nwk_fields(pkt, msg_queue)
        else:
            config.row["error_msg"] = "There are no Zigbee NWK fields"
            return
    elif config.nwk_protocol == Protocol.THREAD:
        thr_fields(pkt, msg_queue)
    else:
        raise ValueError(
            "Unsupported networking protocol for parsing purposes: "
            + "{}".format(config.nwk_protocol),
        )


def mac_beacon_payload(pkt, msg_queue):
    if config.nwk_protocol == Protocol.ZIGBEE:
        if pkt.haslayer(ZigBeeBeacon):
            nwk_fields(pkt, msg_queue)
        else:
            config.row["error_msg"] = "There are no Zigbee beacon fields"
            return
    elif config.nwk_protocol == Protocol.THREAD:
        if pkt.haslayer(ThreadBeacon):
            thr_fields(pkt, msg_queue)
        else:
            config.row["error_msg"] = "There are no Thread beacon fields"
            return
    else:
        raise ValueError(
            "Unsupported networking protocol for parsing purposes: "
            + "{}".format(config.nwk_protocol),
        )


def mac_command_payload(pkt):
    if config.row["mac_cmd_id"].startswith("0x01:"):
        if pkt.haslayer(Dot15d4CmdAssocReq):
            mac_assocreq(pkt)
        else:
            config.row["error_msg"] = (
                "There are no MAC Association Request fields"
            )
            return
    elif config.row["mac_cmd_id"].startswith("0x02:"):
        if pkt.haslayer(Dot15d4CmdAssocResp):
            mac_assocrsp(pkt)
        else:
            config.row["error_msg"] = (
                "There are no MAC Association Response fields"
            )
            return
    elif config.row["mac_cmd_id"].startswith("0x03:"):
        if pkt.haslayer(Dot15d4CmdDisassociation):
            mac_disassoc(pkt)
        else:
            config.row["error_msg"] = (
                "There are no MAC Disassociation Notification fields"
            )
            return
    elif config.row["mac_cmd_id"].startswith("0x04:"):
        # MAC Data Request commands do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.row["error_msg"] = "PE228: Unexpected payload"
            return
    elif config.row["mac_cmd_id"].startswith("0x05:"):
        # MAC PAN ID Conflict Notification commands
        # do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.row["error_msg"] = "PE229: Unexpected payload"
            return
    elif config.row["mac_cmd_id"].startswith("0x06:"):
        # MAC Orphan Notification commands do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.row["error_msg"] = "PE230: Unexpected payload"
            return
    elif config.row["mac_cmd_id"].startswith("0x07:"):
        # MAC Beacon Request commands do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.row["error_msg"] = "PE231: Unexpected payload"
            return
    elif config.row["mac_cmd_id"].startswith("0x08:"):
        if pkt.haslayer(Dot15d4CmdCoordRealign):
            mac_realign(pkt)
        else:
            config.row["error_msg"] = (
                "There are no MAC Coordinator Realignment fields"
            )
            return
    elif config.row["mac_cmd_id"].startswith("0x09:"):
        if pkt.haslayer(Dot15d4CmdGTSReq):
            mac_gtsreq(pkt)
        else:
            config.row["error_msg"] = (
                "There are no MAC GTS Request fields"
            )
            return
    else:
        config.row["error_msg"] = "Invalid MAC command"
        return


def mac_assocreq(pkt):
    # Capability Information field (1 byte)
    # Alternate PAN Coordinator subfield (1 bit)
    if not (
        config.update_row(
            "mac_assocreq_apc",
            pkt[Dot15d4CmdAssocReq].alternate_pan_coordinator,
            APC_STATES,
            "PE212: Unknown APC state",
        )
    ):
        return
    # Device Type subfield (1 bit)
    if not (
        config.update_row(
            "mac_assocreq_devtype",
            pkt[Dot15d4CmdAssocReq].device_type,
            DEVICE_TYPES,
            "PE213: Unknown device type",
        )
    ):
        return
    # Power Source subfield (1 bit)
    if not (
        config.update_row(
            "mac_assocreq_powsrc",
            pkt[Dot15d4CmdAssocReq].power_source,
            POWER_SOURCES,
            "PE214: Unknown power source",
        )
    ):
        return
    # Receiver On When Idle subfield (1 bit)
    if not (
        config.update_row(
            "mac_assocreq_rxidle",
            pkt[Dot15d4CmdAssocReq].receiver_on_when_idle,
            RXIDLE_STATES,
            "PE215: Unknown RX state when idle",
        )
    ):
        return
    # Security Capability subfield (1 bit)
    if not (
        config.update_row(
            "mac_assocreq_seccap",
            pkt[Dot15d4CmdAssocReq].security_capability,
            SECURITY_CAPABILITIES,
            "PE216: Unknown MAC security capability",
        )
    ):
        return
    # Allocate Address subfield (1 bit)
    if not (
        config.update_row(
            "mac_assocreq_allocaddr",
            pkt[Dot15d4CmdAssocReq].allocate_address,
            ALLOCADDR_STATES,
            "PE217: Unknown address allocation",
        )
    ):
        return

    # MAC Association Request commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdAssocReq].payload)) != 0:
        config.row["error_msg"] = "PE225: Unexpected payload"
        return


def mac_assocrsp(pkt):
    # Short Address field (2 bytes)
    config.row["mac_assocrsp_shortaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdAssocResp].short_address,
    )

    # Association Status field (1 byte)
    if not (
        config.update_row(
            "mac_assocrsp_status",
            pkt[Dot15d4CmdAssocResp].association_status,
            ASSOC_STATUSES,
            "PE218: Unknown association status",
        )
    ):
        return

    # MAC Association Response commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdAssocResp].payload)) != 0:
        config.row["error_msg"] = "PE226: Unexpected payload"
        return


def mac_disassoc(pkt):
    # Disassociation Reason field (1 byte)
    if not (
        config.update_row(
            "mac_disassoc_reason",
            pkt[Dot15d4CmdDisassociation].disassociation_reason,
            DISASSOC_REASONS,
            "PE219: Unknown disassociation reason",
        )
    ):
        return

    # MAC Disassociation Notification commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdDisassociation].payload)) != 0:
        config.row["error_msg"] = "PE227: Unexpected payload"
        return


def mac_realign(pkt):
    # PAN Identifier field (2 bytes)
    config.row["mac_realign_panid"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].panid,
    )

    # Coordinator Short Address field (2 bytes)
    config.row["mac_realign_coordaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].coord_address,
    )

    # Channel Number field (1 byte)
    config.row["mac_realign_channel"] = pkt[Dot15d4CmdCoordRealign].channel

    # Short Address field (2 bytes)
    config.row["mac_realign_shortaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].dev_address,
    )

    # Channel Page field (0/1 byte)
    if pkt.haslayer(Dot15d4CmdCoordRealignPage):
        config.row["mac_realign_page"] = (
            pkt[Dot15d4CmdCoordRealignPage].channel_page
        )

        # MAC Coordinator Realignment commands do not contain any other fields
        if len(bytes(pkt[Dot15d4CmdCoordRealignPage].payload)) != 0:
            config.row["error_msg"] = "PE232: Unexpected payload"
            return
    else:
        # MAC Coordinator Realignment commands do not contain any other fields
        if len(bytes(pkt[Dot15d4CmdCoordRealign].payload)) != 0:
            config.row["error_msg"] = "PE233: Unexpected payload"
            return


def mac_gtsreq(pkt):
    # GTS Characteristics field (1 byte)
    # GTS Length subfield (4 bits)
    config.row["mac_gtsreq_length"] = pkt[Dot15d4CmdGTSReq].gts_len
    # GTS Direction subfield (1 bit)
    if not (
        config.update_row(
            "mac_gtsreq_dir",
            pkt[Dot15d4CmdGTSReq].gts_dir,
            GTS_DIRECTIONS,
            "PE220: Unknown GTS direction",
        )
    ):
        return
    # GTS Characteristics Type subfield (1 bit)
    if not (
        config.update_row(
            "mac_gtsreq_chartype",
            pkt[Dot15d4CmdGTSReq].charact_type,
            GTS_CHARACTERISTICS_TYPES,
            "PE221: Unknown GTS characteristics type",
        )
    ):
        return

    # MAC GTS Request commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdGTSReq].payload)) != 0:
        config.row["error_msg"] = "PE234: Unexpected payload"
        return
