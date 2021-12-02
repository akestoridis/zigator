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
import struct

from scapy.all import (
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
    ZigBeeBeacon,
    ZigbeeNWK,
)

from .. import config
from ..enums import Message
from .nwk_fields import nwk_fields


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
    config.entry["mac_show"] = pkt.show(dump=True)
    if pkt[Dot15d4FCS].fcs is None:
        config.entry["error_msg"] = (
            "PE201: The frame check sequence (FCS) field is not included"
        )
        return

    comp_fcs = struct.unpack("<H", pkt.compute_fcs(bytes(pkt)[:-2]))[0]
    if pkt[Dot15d4FCS].fcs != comp_fcs:
        msg_obj = (
            "The received FCS (0x{:04x}), ".format(pkt[Dot15d4FCS].fcs)
            + "for packet #{} ".format(config.entry["pkt_num"])
            + "in {}, ".format(config.entry["pcap_filename"])
            + "does not match the computed FCS (0x{:04x})".format(comp_fcs)
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.entry["error_msg"] = (
            "PE202: Incorrect frame check sequence (FCS)"
        )
        return

    # Frame Check Sequence field (2 bytes)
    config.entry["mac_fcs"] = "0x{:04x}".format(pkt[Dot15d4FCS].fcs)

    # Frame Control field (2 bytes)
    # Frame Type subfield (3 bits)
    if not (
        config.set_entry(
            "mac_frametype",
            pkt[Dot15d4FCS].fcf_frametype,
            MAC_FRAME_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE203: Unknown MAC frame type"
        return
    # Security subfield (1 bit)
    if not (
        config.set_entry(
            "mac_security",
            pkt[Dot15d4FCS].fcf_security,
            MAC_SECURITY_STATES,
        )
    ):
        config.entry["error_msg"] = "PE204: Unknown MAC security state"
        return
    # Frame Pending subfield (1 bit)
    if not (
        config.set_entry(
            "mac_framepending",
            pkt[Dot15d4FCS].fcf_pending,
            MAC_FP_STATES,
        )
    ):
        config.entry["error_msg"] = "PE205: Unknown MAC FP state"
        return
    # Acknowledgment Request subfield (1 bit)
    if not (
        config.set_entry(
            "mac_ackreq",
            pkt[Dot15d4FCS].fcf_ackreq,
            MAC_AR_STATES,
        )
    ):
        config.entry["error_msg"] = "PE206: Unknown MAC AR state"
        return
    # PAN ID Compression subfield (1 bit)
    if not (
        config.set_entry(
            "mac_panidcomp",
            pkt[Dot15d4FCS].fcf_panidcompress,
            MAC_PIC_STATES,
        )
    ):
        config.entry["error_msg"] = "PE207: Unknown MAC PIC state"
        return
    # Destination Addressing Mode subfield (2 bits)
    if not (
        config.set_entry(
            "mac_dstaddrmode",
            pkt[Dot15d4FCS].fcf_destaddrmode,
            MAC_DA_MODES,
        )
    ):
        config.entry["error_msg"] = "PE208: Unknown MAC DA mode"
        return
    # Frame Version subfield (2 bits)
    if not (
        config.set_entry(
            "mac_frameversion",
            pkt[Dot15d4FCS].fcf_framever,
            MAC_FRAME_VERSIONS,
        )
    ):
        config.entry["error_msg"] = "PE209: Unknown MAC frame version"
        return
    # Source Addressing Mode subfield (2 bits)
    if not (
        config.set_entry(
            "mac_srcaddrmode",
            pkt[Dot15d4FCS].fcf_srcaddrmode,
            MAC_SA_MODES,
        )
    ):
        config.entry["error_msg"] = "PE210: Unknown MAC SA mode"
        return

    # Sequence Number field (1 byte)
    config.entry["mac_seqnum"] = pkt[Dot15d4FCS].seqnum

    if config.entry["mac_security"].startswith("0b1:"):
        # Auxiliary Security Header field (0/5/6/10/14 bytes)
        if pkt.haslayer(Dot15d4AuxSecurityHeader):
            # Zigbee does not utilize any security services on the MAC layer
            msg_obj = (
                "The packet #{} ".format(config.entry["pkt_num"])
                + "in {} ".format(config.entry["pcap_filename"])
                + "is utilizing security services on the MAC layer"
            )
            if msg_queue is None:
                logging.debug(msg_obj)
            else:
                msg_queue.put((Message.DEBUG, msg_obj))
            config.entry["error_msg"] = (
                "Ignored the MAC Auxiliary Security Header"
            )
            return
        else:
            config.entry["error_msg"] = (
                "The MAC Auxiliary Security Header is not included"
            )
            return
    elif config.entry["mac_security"].startswith("0b0:"):
        # MAC Payload field (variable)
        if config.entry["mac_frametype"].startswith("0b010:"):
            # MAC Acknowledgments do not contain any other fields
            if len(bytes(pkt[Dot15d4FCS].payload)) != 0:
                config.entry["error_msg"] = "PE224: Unexpected payload"
                return
        elif config.entry["mac_frametype"].startswith("0b001:"):
            if pkt.haslayer(Dot15d4Data):
                mac_data(pkt, msg_queue)
            else:
                config.entry["error_msg"] = "There are no MAC Data fields"
                return
        elif config.entry["mac_frametype"].startswith("0b000:"):
            if pkt.haslayer(Dot15d4Beacon):
                mac_beacon(pkt, msg_queue)
            else:
                config.entry["error_msg"] = "There are no MAC Beacon fields"
                return
        elif config.entry["mac_frametype"].startswith("0b011:"):
            if pkt.haslayer(Dot15d4Cmd):
                mac_command(pkt, msg_queue)
            else:
                config.entry["error_msg"] = "There are no MAC Command fields"
                return
        else:
            config.entry["error_msg"] = "Invalid MAC frame type"
            return
    else:
        config.entry["error_msg"] = "Invalid MAC security state"
        return


def mac_data(pkt, msg_queue):
    # Destination Addressing fields (0/4/10 bytes)
    if config.entry["mac_dstaddrmode"].startswith("0b10:"):
        # Destination PAN ID subfield (2 bytes)
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_panid,
        )
        # Destination Short Address subfield (2 bytes)
        config.entry["mac_dstshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_addr,
        )
    elif config.entry["mac_dstaddrmode"].startswith("0b11:"):
        # Destination PAN ID subfield (2 bytes)
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Data].dest_panid,
        )
        # Destination Extended Address subfield (8 bytes)
        config.entry["mac_dstextendedaddr"] = format(
            pkt[Dot15d4Data].dest_addr,
            "016x",
        )
    elif not config.entry["mac_dstaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = "Invalid MAC DA mode"
        return

    # Source Addressing fields (0/2/4/8/10 bytes)
    if config.entry["mac_srcaddrmode"].startswith("0b10:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Data].src_panid,
            )
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Short Address subfield (2 bytes)
        config.entry["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Data].src_addr,
        )
    elif config.entry["mac_srcaddrmode"].startswith("0b11:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Data].src_panid,
            )
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Extended Address subfield (8 bytes)
        config.entry["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Data].src_addr,
            "016x",
        )
    elif not config.entry["mac_srcaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = "Invalid MAC SA mode"
        return

    # Data Payload field (variable)
    if pkt.haslayer(ZigbeeNWK):
        nwk_fields(pkt, msg_queue)
    else:
        config.entry["error_msg"] = "There are no Zigbee NWK fields"
        return


def mac_beacon(pkt, msg_queue):
    if not config.entry["mac_panidcomp"].startswith("0b0:"):
        config.entry["error_msg"] = (
            "The source PAN ID of MAC Beacons should not be compressed"
        )
        return
    elif not config.entry["mac_dstaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = (
            "MAC Beacons should not contain a destination PAN ID and address"
        )
        return

    # Addressing fields (4/10 bytes)
    # Source PAN ID subfield (2 bytes)
    config.entry["mac_srcpanid"] = "0x{:04x}".format(
        pkt[Dot15d4Beacon].src_panid,
    )
    if config.entry["mac_srcaddrmode"].startswith("0b10:"):
        # Source Short Address subfield (2 bytes)
        config.entry["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Beacon].src_addr,
        )
    elif config.entry["mac_srcaddrmode"].startswith("0b11:"):
        # Source Extended Address subfield (8 bytes)
        config.entry["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Beacon].src_addr,
            "016x",
        )
    elif config.entry["mac_srcaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = (
            "MAC Beacons should contain a source PAN ID and address"
        )
        return
    else:
        config.entry["error_msg"] = "Invalid MAC SA mode"
        return

    # Superframe Specification field (2 bytes)
    # Beacon Order subfield (4 bits)
    config.entry["mac_beacon_beaconorder"] = pkt[Dot15d4Beacon].sf_beaconorder
    # Superframe Order subfield (4 bits)
    config.entry["mac_beacon_sforder"] = pkt[Dot15d4Beacon].sf_sforder
    # Final CAP Slot subfield (4 bits)
    config.entry["mac_beacon_finalcap"] = pkt[Dot15d4Beacon].sf_finalcapslot
    # Battery Life Extension subfield (1 bit)
    config.entry["mac_beacon_ble"] = pkt[Dot15d4Beacon].sf_battlifeextend
    # PAN Coordinator subfield (1 bit)
    if not (
        config.set_entry(
            "mac_beacon_pancoord",
            pkt[Dot15d4Beacon].sf_pancoord,
            PANCOORDINATOR_STATES,
        )
    ):
        config.entry["error_msg"] = "PE222: Unknown PAN coordinator state"
        return
    # Association Permit subfield (1 bit)
    if not (
        config.set_entry(
            "mac_beacon_assocpermit",
            pkt[Dot15d4Beacon].sf_assocpermit,
            ASSOCPERMIT_STATES,
        )
    ):
        config.entry["error_msg"] = "PE223: Unknown association permit state"
        return

    # GTS Specification field (1 byte)
    # GTS Descriptor Count subfield (3 bits)
    config.entry["mac_beacon_gtsnum"] = pkt[Dot15d4Beacon].gts_spec_desccount
    # GTS Permit subfield (1 bit)
    config.entry["mac_beacon_gtspermit"] = pkt[Dot15d4Beacon].gts_spec_permit

    # GTS Directions field (0/1 byte)
    if config.entry["mac_beacon_gtsnum"] > 0:
        # GTS Directions Mask subfield (7 bits)
        config.entry["mac_beacon_gtsmask"] = pkt[Dot15d4Beacon].gts_dir_mask

    # GTS List field (variable)
    if config.entry["mac_beacon_gtsnum"] > 0:
        msg_obj = (
            "Packet #{} ".format(config.entry["pkt_num"])
            + "in {} ".format(config.entry["pcap_filename"])
            + "contains a GTS List field which could not be processed"
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.entry["error_msg"] = "Could not process the GTS List"
        return

    # Pending Address Specification field (1 byte)
    # Number of Short Addresses Pending (3 bits)
    config.entry["mac_beacon_nsap"] = pkt[Dot15d4Beacon].pa_num_short
    # Number of Extended Addresses Pending (3 bits)
    config.entry["mac_beacon_neap"] = pkt[Dot15d4Beacon].pa_num_long

    # Address List field (variable)
    if config.entry["mac_beacon_nsap"] > 0:
        config.entry["mac_beacon_shortaddresses"] = ",".join(
            [
                "0x{:04x}".format(addr)
                for addr in pkt[Dot15d4Beacon].pa_short_addresses
            ],
        )
    if config.entry["mac_beacon_neap"] > 0:
        config.entry["mac_beacon_extendedaddresses"] = ",".join(
            [
                format(addr, "016x")
                for addr in pkt[Dot15d4Beacon].pa_long_addresses
            ],
        )

    # Beacon Payload field (variable)
    if pkt.haslayer(ZigBeeBeacon):
        nwk_fields(pkt, msg_queue)
    else:
        config.entry["error_msg"] = (
            "There is no beacon payload from the Zigbee NWK layer"
        )
        return


def mac_command(pkt, msg_queue):
    # Destination Addressing fields (0/4/10 bytes)
    if config.entry["mac_dstaddrmode"].startswith("0b10:"):
        # Destination PAN ID subfield (2 bytes)
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_panid,
        )
        # Destination Short Address subfield (2 bytes)
        config.entry["mac_dstshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_addr,
        )
    elif config.entry["mac_dstaddrmode"].startswith("0b11:"):
        # Destination PAN ID subfield (2 bytes)
        config.entry["mac_dstpanid"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].dest_panid,
        )
        # Destination Extended Address subfield (8 bytes)
        config.entry["mac_dstextendedaddr"] = format(
            pkt[Dot15d4Cmd].dest_addr,
            "016x",
        )
    elif not config.entry["mac_dstaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = "Invalid MAC DA mode"
        return

    # Source Addressing fields (0/2/4/8/10 bytes)
    if config.entry["mac_srcaddrmode"].startswith("0b10:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Cmd].src_panid,
            )
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Short Address subfield (2 bytes)
        config.entry["mac_srcshortaddr"] = "0x{:04x}".format(
            pkt[Dot15d4Cmd].src_addr,
        )
    elif config.entry["mac_srcaddrmode"].startswith("0b11:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            # Source PAN ID subfield (2 bytes)
            config.entry["mac_srcpanid"] = "0x{:04x}".format(
                pkt[Dot15d4Cmd].src_panid,
            )
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        # Source Extended Address subfield (8 bytes)
        config.entry["mac_srcextendedaddr"] = format(
            pkt[Dot15d4Cmd].src_addr,
            "016x",
        )
    elif not config.entry["mac_srcaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = "Invalid MAC SA mode"
        return

    # Command Frame Identifier field (1 byte)
    if not (
        config.set_entry(
            "mac_cmd_id",
            pkt[Dot15d4Cmd].cmd_id,
            MAC_COMMANDS,
        )
    ):
        config.entry["error_msg"] = "PE211: Unknown MAC command"
        return

    # Compute the MAC Command Payload Length
    # The constant 6 was derived by summing the following:
    #  2: MAC Frame Control
    #  1: MAC Sequence Number
    #  1: MAC Command Frame Identifier
    #  2: MAC Frame Check Sequence
    config.entry["mac_cmd_payloadlength"] = config.entry["phy_length"] - 6
    # Compute the length of the MAC Destination Addressing fields
    if config.entry["mac_dstaddrmode"].startswith("0b10:"):
        config.entry["mac_cmd_payloadlength"] -= 4
    elif config.entry["mac_dstaddrmode"].startswith("0b11:"):
        config.entry["mac_cmd_payloadlength"] -= 10
    elif not config.entry["mac_dstaddrmode"].startswith("0b00:"):
        config.entry["error_msg"] = "Invalid MAC DA mode"
        return
    # Compute the length of the MAC Source Addressing fields
    if config.entry["mac_srcaddrmode"].startswith("0b10:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            config.entry["mac_cmd_payloadlength"] -= 2
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        config.entry["mac_cmd_payloadlength"] -= 2
    elif config.entry["mac_srcaddrmode"].startswith("0b11:"):
        if config.entry["mac_panidcomp"].startswith("0b0:"):
            config.entry["mac_cmd_payloadlength"] -= 2
        elif not config.entry["mac_panidcomp"].startswith("0b1:"):
            config.entry["error_msg"] = "Invalid MAC PIC state"
            return
        config.entry["mac_cmd_payloadlength"] -= 8
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
            "Ignored MAC command with enabled MAC-layer security"
        )
        return
    elif not config.entry["mac_security"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid MAC security state"
        return

    # Command Payload field (variable)
    if config.entry["mac_cmd_id"].startswith("0x01:"):
        if pkt.haslayer(Dot15d4CmdAssocReq):
            mac_assocreq(pkt)
        else:
            config.entry["error_msg"] = (
                "There are no MAC Association Request fields"
            )
            return
    elif config.entry["mac_cmd_id"].startswith("0x02:"):
        if pkt.haslayer(Dot15d4CmdAssocResp):
            mac_assocrsp(pkt)
        else:
            config.entry["error_msg"] = (
                "There are no MAC Association Response fields"
            )
            return
    elif config.entry["mac_cmd_id"].startswith("0x03:"):
        if pkt.haslayer(Dot15d4CmdDisassociation):
            mac_disassoc(pkt)
        else:
            config.entry["error_msg"] = (
                "There are no MAC Disassociation Notification fields"
            )
            return
    elif config.entry["mac_cmd_id"].startswith("0x04:"):
        # MAC Data Request commands do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.entry["error_msg"] = "PE228: Unexpected payload"
            return
    elif config.entry["mac_cmd_id"].startswith("0x05:"):
        # MAC PAN ID Conflict Notification commands
        # do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.entry["error_msg"] = "PE229: Unexpected payload"
            return
    elif config.entry["mac_cmd_id"].startswith("0x06:"):
        # MAC Orphan Notification commands do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.entry["error_msg"] = "PE230: Unexpected payload"
            return
    elif config.entry["mac_cmd_id"].startswith("0x07:"):
        # MAC Beacon Request commands do not contain any other fields
        if len(bytes(pkt[Dot15d4Cmd].payload)) != 0:
            config.entry["error_msg"] = "PE231: Unexpected payload"
            return
    elif config.entry["mac_cmd_id"].startswith("0x08:"):
        if pkt.haslayer(Dot15d4CmdCoordRealign):
            mac_realign(pkt)
        else:
            config.entry["error_msg"] = (
                "There are no MAC Coordinator Realignment fields"
            )
            return
    elif config.entry["mac_cmd_id"].startswith("0x09:"):
        if pkt.haslayer(Dot15d4CmdGTSReq):
            mac_gtsreq(pkt)
        else:
            config.entry["error_msg"] = (
                "There are no MAC GTS Request fields"
            )
            return
    else:
        config.entry["error_msg"] = "Invalid MAC command"
        return


def mac_assocreq(pkt):
    # Capability Information field (1 byte)
    # Alternate PAN Coordinator subfield (1 bit)
    if not (
        config.set_entry(
            "mac_assocreq_apc",
            pkt[Dot15d4CmdAssocReq].alternate_pan_coordinator,
            APC_STATES,
        )
    ):
        config.entry["error_msg"] = "PE212: Unknown APC state"
        return
    # Device Type subfield (1 bit)
    if not (
        config.set_entry(
            "mac_assocreq_devtype",
            pkt[Dot15d4CmdAssocReq].device_type,
            DEVICE_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE213: Unknown device type"
        return
    # Power Source subfield (1 bit)
    if not (
        config.set_entry(
            "mac_assocreq_powsrc",
            pkt[Dot15d4CmdAssocReq].power_source,
            POWER_SOURCES,
        )
    ):
        config.entry["error_msg"] = "PE214: Unknown power source"
        return
    # Receiver On When Idle subfield (1 bit)
    if not (
        config.set_entry(
            "mac_assocreq_rxidle",
            pkt[Dot15d4CmdAssocReq].receiver_on_when_idle,
            RXIDLE_STATES,
        )
    ):
        config.entry["error_msg"] = "PE215: Unknown RX state when idle"
        return
    # Security Capability subfield (1 bit)
    if not (
        config.set_entry(
            "mac_assocreq_seccap",
            pkt[Dot15d4CmdAssocReq].security_capability,
            SECURITY_CAPABILITIES,
        )
    ):
        config.entry["error_msg"] = "PE216: Unknown MAC security capability"
        return
    # Allocate Address subfield (1 bit)
    if not (
        config.set_entry(
            "mac_assocreq_allocaddr",
            pkt[Dot15d4CmdAssocReq].allocate_address,
            ALLOCADDR_STATES,
        )
    ):
        config.entry["error_msg"] = "PE217: Unknown address allocation"
        return

    # MAC Association Request commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdAssocReq].payload)) != 0:
        config.entry["error_msg"] = "PE225: Unexpected payload"
        return


def mac_assocrsp(pkt):
    # Short Address field (2 bytes)
    config.entry["mac_assocrsp_shortaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdAssocResp].short_address,
    )

    # Association Status field (1 byte)
    if not (
        config.set_entry(
            "mac_assocrsp_status",
            pkt[Dot15d4CmdAssocResp].association_status,
            ASSOC_STATUSES,
        )
    ):
        config.entry["error_msg"] = "PE218: Unknown association status"
        return

    # MAC Association Response commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdAssocResp].payload)) != 0:
        config.entry["error_msg"] = "PE226: Unexpected payload"
        return


def mac_disassoc(pkt):
    # Disassociation Reason field (1 byte)
    if not (
        config.set_entry(
            "mac_disassoc_reason",
            pkt[Dot15d4CmdDisassociation].disassociation_reason,
            DISASSOC_REASONS,
        )
    ):
        config.entry["error_msg"] = "PE219: Unknown disassociation reason"
        return

    # MAC Disassociation Notification commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdDisassociation].payload)) != 0:
        config.entry["error_msg"] = "PE227: Unexpected payload"
        return


def mac_realign(pkt):
    # PAN Identifier field (2 bytes)
    config.entry["mac_realign_panid"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].panid,
    )

    # Coordinator Short Address field (2 bytes)
    config.entry["mac_realign_coordaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].coord_address,
    )

    # Channel Number field (1 byte)
    config.entry["mac_realign_channel"] = pkt[Dot15d4CmdCoordRealign].channel

    # Short Address field (2 bytes)
    config.entry["mac_realign_shortaddr"] = "0x{:04x}".format(
        pkt[Dot15d4CmdCoordRealign].dev_address,
    )

    # Channel Page field (0/1 byte)
    if pkt.haslayer(Dot15d4CmdCoordRealignPage):
        config.entry["mac_realign_page"] = (
            pkt[Dot15d4CmdCoordRealignPage].channel_page
        )

        # MAC Coordinator Realignment commands do not contain any other fields
        if len(bytes(pkt[Dot15d4CmdCoordRealignPage].payload)) != 0:
            config.entry["error_msg"] = "PE232: Unexpected payload"
            return
    else:
        # MAC Coordinator Realignment commands do not contain any other fields
        if len(bytes(pkt[Dot15d4CmdCoordRealign].payload)) != 0:
            config.entry["error_msg"] = "PE233: Unexpected payload"
            return


def mac_gtsreq(pkt):
    # GTS Characteristics field (1 byte)
    # GTS Length subfield (4 bits)
    config.entry["mac_gtsreq_length"] = pkt[Dot15d4CmdGTSReq].gts_len
    # GTS Direction subfield (1 bit)
    if not (
        config.set_entry(
            "mac_gtsreq_dir",
            pkt[Dot15d4CmdGTSReq].gts_dir,
            GTS_DIRECTIONS,
        )
    ):
        config.entry["error_msg"] = "PE220: Unknown GTS direction"
        return
    # GTS Characteristics Type subfield (1 bit)
    if not (
        config.set_entry(
            "mac_gtsreq_chartype",
            pkt[Dot15d4CmdGTSReq].charact_type,
            GTS_CHARACTERISTICS_TYPES,
        )
    ):
        config.entry["error_msg"] = "PE221: Unknown GTS characteristics type"
        return

    # MAC GTS Request commands do not contain any other fields
    if len(bytes(pkt[Dot15d4CmdGTSReq].payload)) != 0:
        config.entry["error_msg"] = "PE234: Unexpected payload"
        return
