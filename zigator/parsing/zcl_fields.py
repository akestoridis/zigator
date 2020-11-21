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

from scapy.all import ZigbeeClusterLibrary

from .. import config


ZCL_FRAME_TYPES = {
    0: "0b00: Global Command",
    1: "0b01: Cluster-Specific Command"
}

MS_STATES = {
    0: "0b0: The command is not manufacturer-specific",
    1: "0b1: The command is manufacturer-specific"
}

DIRECTION_STATES = {
    0: "0b0: From the client to the server",
    1: "0b1: From the server to the client"
}

DR_STATES = {
    0: "0b0: A Default Response will be returned",
    1: "0b1: A Default Response will be returned only if there is an error"
}

GLOBAL_COMMANDS = {
    0x00: "0x00: Read Attributes",
    0x01: "0x01: Read Attributes Response",
    0x02: "0x02: Write Attributes",
    0x03: "0x03: Write Attributes Undivided",
    0x04: "0x04: Write Attributes Response",
    0x05: "0x05: Write Attributes No Response",
    0x06: "0x06: Configure Reporting",
    0x07: "0x07: Configure Reporting Response",
    0x08: "0x08: Read Reporting Configuration",
    0x09: "0x09: Read Reporting Configuration Response",
    0x0a: "0x0a: Report Attributes",
    0x0b: "0x0b: Default Response",
    0x0c: "0x0c: Discover Attributes",
    0x0d: "0x0d: Discover Attributes Response",
    0x0e: "0x0e: Read Attributes Structured",
    0x0f: "0x0f: Write Attributes Structured",
    0x10: "0x10: Write Attributes Structured Response",
    0x11: "0x11: Discover Commands Received",
    0x12: "0x12: Discover Commands Received Response",
    0x13: "0x13: Discover Commands Generated",
    0x14: "0x14: Discover Commands Generated Response",
    0x15: "0x15: Discover Commands Extended",
    0x16: "0x16: Discover Commands Extended Response"
}


def zcl_fields(pkt):
    """Parse Zigbee Cluster Library fields."""
    # Frame Control field (1 byte)
    # Frame Type subfield (2 bits)
    if not config.set_entry(
            "zcl_frametype",
            pkt[ZigbeeClusterLibrary].zcl_frametype,
            ZCL_FRAME_TYPES):
        config.entry["error_msg"] = "PE601: Unknown ZCL frame type"
        return
    # Manufacturer Specific subfield (1 bit)
    if not config.set_entry(
            "zcl_manufspecific",
            pkt[ZigbeeClusterLibrary].manufacturer_specific,
            MS_STATES):
        config.entry["error_msg"] = "PE602: Unknown ZCL MS state"
        return
    # Direction subfield (1 bit)
    if not config.set_entry(
            "zcl_direction",
            pkt[ZigbeeClusterLibrary].direction,
            DIRECTION_STATES):
        config.entry["error_msg"] = "PE603: Unknown ZCL direction state"
        return
    # Default Response subfield (1 bit)
    if not config.set_entry(
            "zcl_disdefrsp",
            pkt[ZigbeeClusterLibrary].disable_default_response,
            DR_STATES):
        config.entry["error_msg"] = "PE604: Unknown ZCL DR state"
        return

    # Manufacturer Code field (0/2 bytes)
    if config.entry["zcl_manufspecific"].startswith("0b1:"):
        config.entry["zcl_manufcode"] = "0x{:04x}".format(
            pkt[ZigbeeClusterLibrary].manufacturer_code)
    elif not config.entry["zcl_manufspecific"].startswith("0b0:"):
        config.entry["error_msg"] = "Invalid manufacturer-specific state"
        return

    # Transaction Sequence Number field (1 byte)
    config.entry["zcl_seqnum"] = (
        pkt[ZigbeeClusterLibrary].transaction_sequence
    )

    # Command Identifier field (1 byte)
    if config.entry["zcl_frametype"].startswith("0b00:"):
        if not config.set_entry(
                "zcl_cmd_id",
                pkt[ZigbeeClusterLibrary].command_identifier,
                GLOBAL_COMMANDS):
            config.entry["error_msg"] = "PE605: Unknown global command"
            return
    elif config.entry["zcl_frametype"].startswith("0b01:"):
        # TODO
        config.entry["zcl_cmd_id"] = "Unknown Cluster-Specific command"
    else:
        config.entry["error_msg"] = "Invalid ZCL frame type"
        return

    # ZCL Payload field (variable)
    # TODO
