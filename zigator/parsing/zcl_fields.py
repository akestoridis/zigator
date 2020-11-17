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
    0: "Global Command",
    1: "Cluster-Specific Command"
}

MS_STATES = {
    0: "The command is not manufacturer-specific",
    1: "The command is manufacturer-specific"
}

DIRECTION_STATES = {
    0: "From the client to the server",
    1: "From the server to the client"
}

DR_STATES = {
    0: "A Default Response will be returned",
    1: "A Default Response will be returned only if there is an error"
}

GLOBAL_COMMANDS = {
    0x00: "Read Attributes",
    0x01: "Read Attributes Response",
    0x02: "Write Attributes",
    0x03: "Write Attributes Undivided",
    0x04: "Write Attributes Response",
    0x05: "Write Attributes No Response",
    0x06: "Configure Reporting",
    0x07: "Configure Reporting Response",
    0x08: "Read Reporting Configuration",
    0x09: "Read Reporting Configuration Response",
    0x0a: "Report Attributes",
    0x0b: "Default Response",
    0x0c: "Discover Attributes",
    0x0d: "Discover Attributes Response",
    0x0e: "Read Attributes Structured",
    0x0f: "Write Attributes Structured",
    0x10: "Write Attributes Structured Response",
    0x11: "Discover Commands Received",
    0x12: "Discover Commands Received Response",
    0x13: "Discover Commands Generated",
    0x14: "Discover Commands Generated Response",
    0x15: "Discover Commands Extended",
    0x16: "Discover Commands Extended Response"
}


def zcl_fields(pkt):
    """Parse Zigbee Cluster Library fields."""
    # Frame Control field (1 byte)
    if not config.set_entry(
            "zcl_frametype",
            pkt[ZigbeeClusterLibrary].zcl_frametype,
            ZCL_FRAME_TYPES):
        config.entry["error_msg"] = "Unknown ZCL frame type"
        return
    if not config.set_entry(
            "zcl_manufspecific",
            pkt[ZigbeeClusterLibrary].manufacturer_specific,
            MS_STATES):
        config.entry["error_msg"] = "Unknown manufacturer-specific state"
        return
    if not config.set_entry(
            "zcl_direction",
            pkt[ZigbeeClusterLibrary].direction,
            DIRECTION_STATES):
        config.entry["error_msg"] = "Unknown direction state"
        return
    if not config.set_entry(
            "zcl_disdefrsp",
            pkt[ZigbeeClusterLibrary].disable_default_response,
            DR_STATES):
        config.entry["error_msg"] = "Unknown DR state"
        return

    if (config.entry["zcl_manufspecific"]
            == "The command is manufacturer-specific"):
        # Manufacturer Code field (2 bytes)
        config.entry["zcl_manufcode"] = "0x{:04x}".format(
            pkt[ZigbeeClusterLibrary].manufacturer_code)
    elif (config.entry["zcl_manufspecific"]
            != "The command is not manufacturer-specific"):
        config.entry["error_msg"] = "Invalid manufacturer-specific state"
        return

    # Transaction Sequence Number field (1 byte)
    config.entry["zcl_seqnum"] = (
        pkt[ZigbeeClusterLibrary].transaction_sequence
    )

    # Command Identifier field (1 byte)
    if config.entry["zcl_frametype"] == "Global Command":
        if not config.set_entry(
                "zcl_cmd_id",
                pkt[ZigbeeClusterLibrary].command_identifier,
                GLOBAL_COMMANDS):
            config.entry["error_msg"] = "Unknown global command"
            return
    elif config.entry["zcl_frametype"] == "Cluster-Specific Command":
        # TODO
        config.entry["zcl_cmd_id"] = "Unknown Cluster-Specific command"
    else:
        config.entry["error_msg"] = "Invalid ZCL frame type"
        return

    # ZCL Payload field (variable)
    # TODO
