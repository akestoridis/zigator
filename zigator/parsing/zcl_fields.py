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
from .zcl_getters import get_zcl_clusterspecificcommand
from .zcl_getters import get_zcl_direction
from .zcl_getters import get_zcl_disdefrsp
from .zcl_getters import get_zcl_frametype
from .zcl_getters import get_zcl_globalcommand
from .zcl_getters import get_zcl_manufspecific


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
        config.entry["zcl_manufcode"] = "0x{:04x}".format(
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
