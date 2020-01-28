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

from scapy.all import ZigBeeBeacon

from .. import config


def get_nwk_protocolversion(pkt):
    protocol_versions = {
            1: "Zigbee 2004",
            2: "Zigbee PRO",
            3: "Zigbee Green Power"
    }
    prot_ver = pkt[ZigBeeBeacon].nwkc_protocol_version
    return protocol_versions.get(prot_ver, "Unknown NWK protocol version")


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

    # TODO
