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


def get_zcl_frametype(pkt):
    zcl_frame_types = {
        0: "Global Command",
        1: "Cluster-Specific Command"
    }
    frametype_id = pkt[ZigbeeClusterLibrary].zcl_frametype
    return zcl_frame_types.get(frametype_id, "Unknown ZCL frame type")


def get_zcl_manufspecific(pkt):
    ms_states = {
        0: "The command is not manufacturer-specific",
        1: "The command is manufacturer-specific"
    }
    ms_state = pkt[ZigbeeClusterLibrary].manufacturer_specific
    return ms_states.get(ms_state, "Unknown Manufacturer-Specific state")


def get_zcl_direction(pkt):
    direction_states = {
        0: "From the client to the server",
        1: "From the server to the client"
    }
    dir_state = pkt[ZigbeeClusterLibrary].direction
    return direction_states.get(dir_state, "Unknown Direction state")


def get_zcl_disdefrsp(pkt):
    disdefrsp_states = {
        0: "A Default Response will be returned",
        1: "A Default Response will be returned only if there is an error"
    }
    ddr_state = pkt[ZigbeeClusterLibrary].disable_default_response
    return disdefrsp_states.get(ddr_state, "Unknown Default Response state")


def get_zcl_globalcommand(pkt):
    zcl_globalcommands = {
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
    zcl_cmd_id = pkt[ZigbeeClusterLibrary].command_identifier
    return zcl_globalcommands.get(zcl_cmd_id, "Unknown Global command")


def get_zcl_clusterspecificcommand(pkt):
    # TODO
    return "Unknown Cluster-Specific command"


def zcl_fields(pkt):
    """Parse Zigbee Cluster Library fields."""
    # Frame Control field (1 byte)
    config.entry["zcl_frametype"] = get_zcl_frametype(pkt)
    config.entry["zcl_manufspecific"] = get_zcl_manufspecific(pkt)
    config.entry["zcl_direction"] = get_zcl_direction(pkt)
    config.entry["zcl_disdefrsp"] = get_zcl_disdefrsp(pkt)

    if (config.entry["zcl_manufspecific"]
            == "The command is manufacturer-specific"):
        # Manufacturer Code field (2 bytes)
        config.entry["zcl_manufcode"] = hex(
            pkt[ZigbeeClusterLibrary].manufacturer_code)
    elif (config.entry["zcl_manufspecific"]
            != "The command is not manufacturer-specific"):
        config.entry["error_msg"] = "Unknown Manufacturer-Specific state"
        return

    # Transaction Sequence Number field (1 byte)
    config.entry["zcl_seqnum"] = (
        pkt[ZigbeeClusterLibrary].transaction_sequence
    )

    # Command Identifier field (1 byte)
    if config.entry["zcl_frametype"] == "Global Command":
        config.entry["zcl_cmd_id"] = get_zcl_globalcommand(pkt)
    elif config.entry["zcl_frametype"] == "Cluster-Specific Command":
        config.entry["zcl_cmd_id"] = get_zcl_clusterspecificcommand(pkt)
    else:
        config.entry["error_msg"] = "Unknown ZCL frame type"
        return

    # ZCL Payload field (variable)
    # TODO

    return
