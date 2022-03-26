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
import os

from scapy.all import (
    ZigbeeAppCommandPayload,
    ZigbeeAppDataPayload,
    ZigbeeClusterLibrary,
    ZigbeeDeviceProfile,
    ZigbeeSecurityHeader,
)

from .. import (
    config,
    crypto,
)
from ..enums import Message
from .zcl_fields import zcl_fields
from .zdp_fields import zdp_fields


APS_FRAME_TYPES = {
    0: "0b00: APS Data",
    1: "0b01: APS Command",
    2: "0b10: APS Acknowledgment",
    3: "0b11: APS Inter-PAN",
}

APS_DELIVERY_MODES = {
    0: "0b00: Normal unicast delivery",
    2: "0b10: Broadcast",
    3: "0b11: Group addressing",
}

APS_ACKFORMAT_STATES = {
    False: "0b0: APS ACK Format Disabled",
    True: "0b1: APS ACK Format Enabled",
}

APS_SECURITY_STATES = {
    False: "0b0: APS Security Disabled",
    True: "0b1: APS Security Enabled",
}

APS_AR_STATES = {
    False: "0b0: The sender does not request an APS ACK",
    True: "0b1: The sender requests an APS ACK",
}

APS_EH_STATES = {
    False: "0b0: The extended header is not included",
    True: "0b1: The extended header is included",
}

APS_PROFILES = {
    0x0000: "0x0000: Zigbee Device Profile (ZDP)",
    0x0104: "0x0104: Zigbee Home Automation (ZHA)",
}

ZDP_CLUSTERS = {
    0x0000: "0x0000: NWK_addr_req",
    0x0001: "0x0001: IEEE_addr_req",
    0x0002: "0x0002: Node_Desc_req",
    0x0003: "0x0003: Power_Desc_req",
    0x0004: "0x0004: Simple_Desc_req",
    0x0005: "0x0005: Active_EP_req",
    0x0006: "0x0006: Match_Desc_req",
    0x0010: "0x0010: Complex_Desc_req",
    0x0011: "0x0011: User_Desc_req",
    0x0012: "0x0012: Discovery_Cache_req",
    0x0013: "0x0013: Device_annce",
    0x0014: "0x0014: User_Desc_set",
    0x0015: "0x0015: System_Server_Discovery_req",
    0x0016: "0x0016: Discovery_store_req",
    0x0017: "0x0017: Node_Desc_store_req",
    0x0018: "0x0018: Power_Desc_store_req",
    0x0019: "0x0019: Active_EP_store_req",
    0x001a: "0x001a: Simple_Desc_store_req",
    0x001b: "0x001b: Remove_node_cache_req",
    0x001c: "0x001c: Find_node_cache_req",
    0x001d: "0x001d: Extended_Simple_Desc_req",
    0x001e: "0x001e: Extended_Active_EP_req",
    0x001f: "0x001f: Parent_annce",
    0x0020: "0x0020: End_Device_Bind_req",
    0x0021: "0x0021: Bind_req",
    0x0022: "0x0022: Unbind_req",
    0x0023: "0x0023: Bind_Register_req",
    0x0024: "0x0024: Replace_Device_req",
    0x0025: "0x0025: Store_Bkup_Bind_Entry_req",
    0x0026: "0x0026: Remove_Bkup_Bind_Entry_req",
    0x0027: "0x0027: Backup_Bind_Table_req",
    0x0028: "0x0028: Recover_Bind_Table_req",
    0x0029: "0x0029: Backup_Source_Bind_req",
    0x002a: "0x002a: Recover_Source_Bind_req",
    0x0030: "0x0030: Mgmt_NWK_Disc_req",
    0x0031: "0x0031: Mgmt_Lqi_req",
    0x0032: "0x0032: Mgmt_Rtg_req",
    0x0033: "0x0033: Mgmt_Bind_req",
    0x0034: "0x0034: Mgmt_Leave_req",
    0x0035: "0x0035: Mgmt_Direct_Join_req",
    0x0036: "0x0036: Mgmt_Permit_Joining_req",
    0x0037: "0x0037: Mgmt_Cache_req",
    0x0038: "0x0038: Mgmt_NWK_Update_req",
    0x8000: "0x8000: NWK_addr_rsp",
    0x8001: "0x8001: IEEE_addr_rsp",
    0x8002: "0x8002: Node_Desc_rsp",
    0x8003: "0x8003: Power_Desc_rsp",
    0x8004: "0x8004: Simple_Desc_rsp",
    0x8005: "0x8005: Active_EP_rsp",
    0x8006: "0x8006: Match_Desc_rsp",
    0x8010: "0x8010: Complex_Desc_rsp",
    0x8011: "0x8011: User_Desc_rsp",
    0x8012: "0x8012: Discovery_Cache_rsp",
    0x8014: "0x8014: User_Desc_conf",
    0x8015: "0x8015: System_Server_Discovery_rsp",
    0x8016: "0x8016: Discovery_store_rsp",
    0x8017: "0x8017: Node_Desc_store_rsp",
    0x8018: "0x8018: Power_Desc_store_rsp",
    0x8019: "0x8019: Active_EP_store_rsp",
    0x801a: "0x801a: Simple_Desc_store_rsp",
    0x801b: "0x801b: Remove_node_cache_rsp",
    0x801c: "0x801c: Find_node_cache_rsp",
    0x801d: "0x801d: Extended_Simple_Desc_rsp",
    0x801e: "0x801e: Extended_Active_EP_rsp",
    0x801f: "0x801f: Parent_annce_rsp",
    0x8020: "0x8020: End_Device_Bind_rsp",
    0x8021: "0x8021: Bind_rsp",
    0x8022: "0x8022: Unbind_rsp",
    0x8023: "0x8023: Bind_Register_rsp",
    0x8024: "0x8024: Replace_Device_rsp",
    0x8025: "0x8025: Store_Bkup_Bind_Entry_rsp",
    0x8026: "0x8026: Remove_Bkup_Bind_Entry_rsp",
    0x8027: "0x8027: Backup_Bind_Table_rsp",
    0x8028: "0x8028: Recover_Bind_Table_rsp",
    0x8029: "0x8029: Backup_Source_Bind_rsp",
    0x802a: "0x802a: Recover_Source_Bind_rsp",
    0x8030: "0x8030: Mgmt_NWK_Disc_rsp",
    0x8031: "0x8031: Mgmt_Lqi_rsp",
    0x8032: "0x8032: Mgmt_Rtg_rsp",
    0x8033: "0x8033: Mgmt_Bind_rsp",
    0x8034: "0x8034: Mgmt_Leave_rsp",
    0x8035: "0x8035: Mgmt_Direct_Join_rsp",
    0x8036: "0x8036: Mgmt_Permit_Joining_rsp",
    0x8037: "0x8037: Mgmt_Cache_rsp",
    0x8038: "0x8038: Mgmt_NWK_Update_notify",
}

ZCL_CLUSTERS = {
    0x0000: "0x0000: Basic",
    0x0001: "0x0001: Power Configuration",
    0x0002: "0x0002: Device Temperature Configuration",
    0x0003: "0x0003: Identify",
    0x0004: "0x0004: Groups",
    0x0005: "0x0005: Scenes",
    0x0006: "0x0006: On/Off",
    0x0007: "0x0007: On/Off Switch Configuration",
    0x0008: "0x0008: Level Control",
    0x0009: "0x0009: Alarms",
    0x000a: "0x000a: Time",
    0x000b: "0x000b: RSSI Location",
    0x000c: "0x000c: Analog Input (basic)",
    0x000d: "0x000d: Analog Output (basic)",
    0x000e: "0x000e: Analog Value (basic)",
    0x000f: "0x000f: Binary Input (basic)",
    0x0010: "0x0010: Binary Output (basic)",
    0x0011: "0x0011: Binary Value (basic)",
    0x0012: "0x0012: Multistate Input (basic)",
    0x0013: "0x0013: Multistate Output (basic)",
    0x0014: "0x0014: Multistate Value (basic)",
    0x0015: "0x0015: Commissioning",
    0x0016: "0x0016: Partition",
    0x0019: "0x0019: OTA Upgrade",
    0x001a: "0x001a: Power Profile",
    0x001b: "0x001b: EN50523 Appliance Control",
    0x0020: "0x0020: Poll Control",
    0x0022: "0x0022: Mobile Device Configuration Cluster",
    0x0023: "0x0023: Neighbor Cleaning Cluster",
    0x0024: "0x0024: Nearest Gateway Cluster",
    0x0100: "0x0100: Shade Configuration",
    0x0101: "0x0101: Door Lock",
    0x0102: "0x0102: Window Covering",
    0x0200: "0x0200: Pump Configuration and Control",
    0x0201: "0x0201: Thermostat",
    0x0202: "0x0202: Fan Control",
    0x0203: "0x0203: Dehumidification Control",
    0x0204: "0x0204: Thermostat User Interface Configuration",
    0x0300: "0x0300: Color Control",
    0x0301: "0x0301: Ballast Configuration",
    0x0400: "0x0400: Illuminance Measurement",
    0x0401: "0x0401: Illuminance Level Sensing",
    0x0402: "0x0402: Temperature Measurement",
    0x0403: "0x0403: Pressure Measurement",
    0x0404: "0x0404: Flow Measurement",
    0x0405: "0x0405: Relative Humidity Measurement",
    0x0406: "0x0406: Occupancy Sensing",
    0x0500: "0x0500: IAS Zone",
    0x0501: "0x0501: IAS ACE",
    0x0502: "0x0502: IAS WD",
    0x0600: "0x0600: Generic Tunnel",
    0x0601: "0x0601: BACnet Protocol Tunnel",
    0x0602: "0x0602: Analog Input (BACnet regular)",
    0x0603: "0x0603: Analog Input (BACnet extended)",
    0x0604: "0x0604: Analog Output (BACnet regular)",
    0x0605: "0x0605: Analog Output (BACnet extended)",
    0x0606: "0x0606: Analog Value (BACnet regular)",
    0x0607: "0x0607: Analog Value (BACnet extended)",
    0x0608: "0x0608: Binary Input (BACnet regular)",
    0x0609: "0x0609: Binary Input (BACnet extended)",
    0x060a: "0x060a: Binary Output (BACnet regular)",
    0x060b: "0x060b: Binary Output (BACnet extended)",
    0x060c: "0x060c: Binary Value (BACnet regular)",
    0x060d: "0x060d: Binary Value (BACnet extended)",
    0x060e: "0x060e: Multistate Input (BACnet regular)",
    0x060f: "0x060f: Multistate Input (BACnet extended)",
    0x0610: "0x0610: Multistate Output (BACnet regular)",
    0x0611: "0x0611: Multistate Output (BACnet extended)",
    0x0612: "0x0612: Multistate Value (BACnet regular)",
    0x0613: "0x0613: Multistate Value (BACnet extended)",
    0x0614: "0x0614: 11073 Protocol Tunnel",
    0x0615: "0x0615: ISO7816 Tunnel",
    0x0617: "0x0617: Retail Tunnel Cluster",
    0x0700: "0x0700: Price",
    0x0701: "0x0701: Demand Response and Local Control",
    0x0702: "0x0702: Metering",
    0x0703: "0x0703: Messaging",
    0x0704: "0x0704: Tunneling",
    0x0800: "0x0800: Key Establishment",
    0x0900: "0x0900: Information",
    0x0904: "0x0904: Voice over Zigbee",
    0x0905: "0x0905: Chatting",
    0x0b00: "0x0b00: EN50523 Appliance Identification",
    0x0b01: "0x0b01: Meter Identification",
    0x0b02: "0x0b02: EN50523 Appliance Events and Alerts",
    0x0b03: "0x0b03: EN50523 Appliance Statistics",
    0x0b04: "0x0b04: Electrical Measurement",
    0x0b05: "0x0b05: Diagnostics",
    0x1000: "0x1000: Touchlink",
}

FRAGMENTATION_STATES = {
    0: "0b00: No fragmentation",
    1: "0b01: First fragment",
    2: "0b10: Continued fragment",
}

APS_SECURITY_LEVELS = {
    0: "0b000: None",
    1: "0b001: MIC-32",
    2: "0b010: MIC-64",
    3: "0b011: MIC-128",
    4: "0b100: ENC",
    5: "0b101: ENC-MIC-32",
    6: "0b110: ENC-MIC-64",
    7: "0b111: ENC-MIC-128",
}

APS_KEY_TYPES = {
    0: "0b00: Data Key",
    1: "0b01: Network Key",
    2: "0b10: Key-Transport Key",
    3: "0b11: Key-Load Key",
}

APS_EN_STATES = {
    0: "0b0: The source address is not present",
    1: "0b1: The source address is present",
}

APS_COMMANDS = {
    5: "0x05: APS Transport Key",
    6: "0x06: APS Update Device",
    7: "0x07: APS Remove Device",
    8: "0x08: APS Request Key",
    9: "0x09: APS Switch Key",
    14: "0x0e: APS Tunnel",
    15: "0x0f: APS Verify Key",
    16: "0x10: APS Confirm Key",
}

STANDARD_KEY_TYPES = {
    1: "0x01: Standard Network Key",
    3: "0x03: Application Link Key",
    4: "0x04: Trust Center Link Key",
}

IF_STATES = {
    0: "0x00: The receiver did not request this key",
    1: "0x01: The receiver requested this key",
}

UD_STATUSES = {
    0: "0x00: Standard device secured rejoin",
    1: "0x01: Standard device unsecured rejoin",
    2: "0x02: Device left",
    3: "0x03: Standard device trust center rejoin",
}

REQUEST_KEY_TYPES = {
    2: "0x02: Application Link Key",
    4: "0x04: Trust Center Link Key",
}

CONFIRM_STATUSES = {
    0x00: "0x00: SUCCESS",
    0xa0: "0xa0: ASDU_TOO_LONG",
    0xa1: "0xa1: DEFRAG_DEFERRED",
    0xa2: "0xa2: DEFRAG_UNSUPPORTED",
    0xa3: "0xa3: ILLEGAL_REQUEST",
    0xa4: "0xa4: INVALID_BINDING",
    0xa5: "0xa5: INVALID_GROUP",
    0xa6: "0xa6: INVALID_PARAMETER",
    0xa7: "0xa7: NO_ACK",
    0xa8: "0xa8: NO_BOUND_DEVICE",
    0xa9: "0xa9: NO_SHORT_ADDRESS",
    0xaa: "0xaa: NOT_SUPPORTED",
    0xab: "0xab: SECURED_LINK_KEY",
    0xac: "0xac: SECURED_NWK_KEY",
    0xad: "0xad: SECURITY_FAIL",
    0xae: "0xae: TABLE_FULL",
    0xaf: "0xaf: UNSECURED",
    0xb0: "0xb0: UNSUPPORTED_ATTRIBUTE",
}


def aps_fields(pkt, msg_queue):
    """Parse Zigbee APS fields."""
    # Frame Control field (1 byte)
    # Frame Type subfield (2 bits)
    if not (
        config.update_row(
            "aps_frametype",
            pkt[ZigbeeAppDataPayload].aps_frametype,
            APS_FRAME_TYPES,
            "PE401: Unknown APS frame type",
        )
    ):
        return
    # Delivery Mode subfield (2 bits)
    if not (
        config.update_row(
            "aps_delmode",
            pkt[ZigbeeAppDataPayload].delivery_mode,
            APS_DELIVERY_MODES,
            "PE402: Unknown APS delivery mode",
        )
    ):
        return
    # ACK Format subfield (1 bit)
    if not (
        config.update_row(
            "aps_ackformat",
            pkt[ZigbeeAppDataPayload].frame_control.ack_format,
            APS_ACKFORMAT_STATES,
            "PE403: Unknown APS ACK format state",
        )
    ):
        return
    # Security subfield (1 bit)
    if not (
        config.update_row(
            "aps_security",
            pkt[ZigbeeAppDataPayload].frame_control.security,
            APS_SECURITY_STATES,
            "PE404: Unknown APS security state",
        )
    ):
        return
    # Acknowledgment Request subfield (1 bit)
    if not (
        config.update_row(
            "aps_ackreq",
            pkt[ZigbeeAppDataPayload].frame_control.ack_req,
            APS_AR_STATES,
            "PE405: Unknown APS AR state",
        )
    ):
        return
    # Extended Header subfield (1 bit)
    if not (
        config.update_row(
            "aps_exthdr",
            pkt[ZigbeeAppDataPayload].frame_control.extended_hdr,
            APS_EH_STATES,
            "PE406: Unknown APS EH state",
        )
    ):
        return

    # The APS Header fields vary significantly between different frame types
    if config.row["aps_frametype"].startswith("0b00:"):
        aps_data_header(pkt, msg_queue)
    elif config.row["aps_frametype"].startswith("0b10:"):
        aps_ack_header(pkt, msg_queue)
    elif config.row["aps_frametype"].startswith("0b01:"):
        aps_command_header(pkt, msg_queue)
    elif config.row["aps_frametype"].startswith("0b11:"):
        msg_obj = (
            "Packet #{} ".format(config.row["pkt_num"])
            + "in {} ".format(config.row["pcap_filename"])
            + "contains Inter-PAN fields which were ignored"
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.row["error_msg"] = "Ignored the Inter-PAN fields"
        return
    else:
        config.row["error_msg"] = "Invalid APS frame type"
        return


def aps_data_header(pkt, msg_queue):
    if (
        config.row["aps_delmode"].startswith("0b00:")
        or config.row["aps_delmode"].startswith("0b10:")
    ):
        # Destination Endpoint field (1 byte)
        config.row["aps_dstendpoint"] = pkt[ZigbeeAppDataPayload].dst_endpoint
    elif config.row["aps_delmode"].startswith("0b11:"):
        # Group Address field (2 bytes)
        config.row["aps_groupaddr"] = "0x{:04x}".format(
            pkt[ZigbeeAppDataPayload].group_addr,
        )
    else:
        config.row["error_msg"] = "Invalid APS delivery mode"
        return

    # Profile Identifier field (2 bytes)
    if not (
        config.update_row(
            "aps_profile_id",
            pkt[ZigbeeAppDataPayload].profile,
            APS_PROFILES,
        )
    ):
        config.row["aps_profile_id"] = "0x{:04x}: Unknown APS profile".format(
            pkt[ZigbeeAppDataPayload].profile,
        )

    # Cluster Identifier field (2 bytes)
    if config.row["aps_profile_id"].startswith("0x0000:"):
        if not (
            config.update_row(
                "aps_cluster_id",
                pkt[ZigbeeAppDataPayload].cluster,
                ZDP_CLUSTERS,
            )
        ):
            config.row["aps_cluster_id"] = (
                "0x{:04x}: Unknown ZDP cluster".format(
                    pkt[ZigbeeAppDataPayload].cluster,
                )
            )
    elif config.row["aps_profile_id"].split()[1] != "Unknown":
        if not (
            config.update_row(
                "aps_cluster_id",
                pkt[ZigbeeAppDataPayload].cluster,
                ZCL_CLUSTERS,
            )
        ):
            config.row["aps_cluster_id"] = (
                "0x{:04x}: Unknown ZCL cluster".format(
                    pkt[ZigbeeAppDataPayload].cluster,
                )
            )
    else:
        config.row["aps_cluster_id"] = "0x{:04x}: Unknown APS cluster".format(
            pkt[ZigbeeAppDataPayload].cluster,
        )

    # Source Endpoint field (1 byte)
    config.row["aps_srcendpoint"] = pkt[ZigbeeAppDataPayload].src_endpoint

    # APS Counter field (1 byte)
    config.row["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    # Extended Header field (0/1/2 bytes)
    if config.row["aps_exthdr"].startswith("0b1:"):
        # Extended Frame Control subfield (1 byte)
        # Fragmentation subsubfield (2 bits)
        if not (
            config.update_row(
                "aps_fragmentation",
                pkt[ZigbeeAppDataPayload].fragmentation,
                FRAGMENTATION_STATES,
                "PE407: Unknown fragmentation state",
            )
        ):
            return

        if (
            config.row["aps_fragmentation"].startswith("0b01:")
            or config.row["aps_fragmentation"].startswith("0b10:")
        ):
            # Block Number subfield (1 byte)
            config.row["aps_blocknumber"] = (
                pkt[ZigbeeAppDataPayload].block_number
            )
        elif not config.row["aps_fragmentation"].startswith("0b00:"):
            config.row["error_msg"] = "Invalid fragmentation state"
            return
    elif not config.row["aps_exthdr"].startswith("0b0:"):
        config.row["error_msg"] = "Invalid APS EH state"
        return

    if config.row["aps_security"].startswith("0b1:"):
        # APS Auxiliary Header field (5/6/13/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            aps_auxiliary(pkt, msg_queue, tunneled=False)
        else:
            config.row["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.row["aps_security"].startswith("0b0:"):
        # APS Data fields (variable)
        if config.row["aps_profile_id"].startswith("0x0000:"):
            if pkt.haslayer(ZigbeeDeviceProfile):
                zdp_fields(pkt)
            else:
                config.row["error_msg"] = "There are no ZDP fields"
                return
        elif config.row["aps_profile_id"].split()[1] != "Unknown":
            if pkt.haslayer(ZigbeeClusterLibrary):
                zcl_fields(pkt)
            else:
                config.row["error_msg"] = "There are no ZCL fields"
                return
        else:
            config.row["error_msg"] = "Unknown APS profile with ID {}".format(
                config.row["aps_profile_id"],
            )
            return
    else:
        config.row["error_msg"] = "Invalid APS security state"
        return


def aps_ack_header(pkt, msg_queue):
    if config.row["aps_ackformat"].startswith("0b0:"):
        # Destination Endpoint field (1 byte)
        config.row["aps_dstendpoint"] = pkt[ZigbeeAppDataPayload].dst_endpoint

        # Profile Identifier field (2 bytes)
        if not (
            config.update_row(
                "aps_profile_id",
                pkt[ZigbeeAppDataPayload].profile,
                APS_PROFILES,
            )
        ):
            config.row["aps_profile_id"] = (
                "0x{:04x}: Unknown APS profile".format(
                    pkt[ZigbeeAppDataPayload].profile,
                )
            )

        # Cluster Identifier field (2 bytes)
        if config.row["aps_profile_id"].startswith("0x0000:"):
            if not (
                config.update_row(
                    "aps_cluster_id",
                    pkt[ZigbeeAppDataPayload].cluster,
                    ZDP_CLUSTERS,
                )
            ):
                config.row["aps_cluster_id"] = (
                    "0x{:04x}: Unknown ZDP cluster".format(
                        pkt[ZigbeeAppDataPayload].cluster,
                    )
                )
        elif config.row["aps_profile_id"].split()[1] != "Unknown":
            if not (
                config.update_row(
                    "aps_cluster_id",
                    pkt[ZigbeeAppDataPayload].cluster,
                    ZCL_CLUSTERS,
                )
            ):
                config.row["aps_cluster_id"] = (
                    "0x{:04x}: Unknown ZCL cluster".format(
                        pkt[ZigbeeAppDataPayload].cluster,
                    )
                )
        else:
            config.row["aps_cluster_id"] = (
                "0x{:04x}: Unknown APS cluster".format(
                    pkt[ZigbeeAppDataPayload].cluster,
                )
            )

        # Source Endpoint field (1 byte)
        config.row["aps_srcendpoint"] = pkt[ZigbeeAppDataPayload].src_endpoint
    elif not config.row["aps_ackformat"].startswith("0b1:"):
        config.row["error_msg"] = "Invalid ACK Format state"
        return

    # APS Counter field (1 byte)
    config.row["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    # Extended Header field (0/1/3 bytes)
    if config.row["aps_exthdr"].startswith("0b1:"):
        # Extended Frame Control subfield (1 byte)
        # Fragmentation subsubfield (2 bits)
        if not (
            config.update_row(
                "aps_fragmentation",
                pkt[ZigbeeAppDataPayload].fragmentation,
                FRAGMENTATION_STATES,
                "PE408: Unknown fragmentation state",
            )
        ):
            return

        if (
            config.row["aps_fragmentation"].startswith("0b01:")
            or config.row["aps_fragmentation"].startswith("0b10:")
        ):
            # Block Number subfield (1 byte)
            config.row["aps_blocknumber"] = (
                pkt[ZigbeeAppDataPayload].block_number
            )

            # ACK Bitfield subfield (1 byte)
            config.row["aps_ackbitfield"] = (
                pkt[ZigbeeAppDataPayload].ack_bitfield
            )
        elif not config.row["aps_fragmentation"].startswith("0b00:"):
            config.row["error_msg"] = "Invalid fragmentation state"
            return
    elif not config.row["aps_exthdr"].startswith("0b0:"):
        config.row["error_msg"] = "Invalid APS EH state"
        return

    if config.row["aps_security"].startswith("0b1:"):
        # APS Auxiliary Header field (5/6/13/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            aps_auxiliary(pkt, msg_queue, tunneled=False)
        else:
            config.row["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.row["aps_security"].startswith("0b0:"):
        # APS Acknowledgments do not contain any other fields
        if len(bytes(pkt[ZigbeeAppDataPayload].payload)) != 0:
            config.row["error_msg"] = "PE426: Unexpected payload"
            return
    else:
        config.row["error_msg"] = "Invalid APS security state"
        return


def aps_command_header(pkt, msg_queue):
    # APS Counter field (1 byte)
    config.row["aps_counter"] = pkt[ZigbeeAppDataPayload].counter

    if config.row["aps_security"].startswith("0b1:"):
        # APS Auxiliary Header field (5/6/13/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            aps_auxiliary(pkt, msg_queue, tunneled=False)
        else:
            config.row["error_msg"] = (
                "The APS Auxiliary Header is not included"
            )
            return
    elif config.row["aps_security"].startswith("0b0:"):
        # APS Command fields (variable)
        if pkt.haslayer(ZigbeeAppCommandPayload):
            aps_command_payload(pkt, msg_queue, tunneled=False)
        else:
            config.row["error_msg"] = "There are no APS Command fields"
            return
    else:
        config.row["error_msg"] = "Invalid APS security state"
        return


def aps_auxiliary(pkt, msg_queue, tunneled=False):
    # Security Control field (1 byte)
    # Security Level subfield (3 bits)
    if not (
        config.update_row(
            "aps_aux_seclevel",
            pkt[ZigbeeSecurityHeader].nwk_seclevel,
            APS_SECURITY_LEVELS,
            "PE409: Unknown APS security level",
        )
    ):
        return
    # Key Identifier subfield (2 bits)
    if not (
        config.update_row(
            "aps_aux_keytype",
            pkt[ZigbeeSecurityHeader].key_type,
            APS_KEY_TYPES,
            "PE410: Unknown APS key type",
        )
    ):
        return
    # Extended Nonce subfield (1 bit)
    if not (
        config.update_row(
            "aps_aux_extnonce",
            pkt[ZigbeeSecurityHeader].extended_nonce,
            APS_EN_STATES,
            "PE411: Unknown APS EN state",
        )
    ):
        return

    # Frame Counter field (4 bytes)
    config.row["aps_aux_framecounter"] = pkt[ZigbeeSecurityHeader].fc
    frame_counter = pkt[ZigbeeSecurityHeader].fc

    # Source Address field (0/8 bytes)
    if config.row["aps_aux_extnonce"].startswith("0b1:"):
        config.row["aps_aux_srcaddr"] = format(
            pkt[ZigbeeSecurityHeader].source,
            "016x",
        )
        potential_sources = {
            pkt[ZigbeeSecurityHeader].source,
        }
    elif config.row["aps_aux_extnonce"].startswith("0b0:"):
        panid = config.row["mac_dstpanid"]
        shortaddr = config.row["nwk_srcshortaddr"]
        potential_sources = config.get_alternative_addresses(panid, shortaddr)

        if len(potential_sources) == 0:
            potential_sources = {
                int(extendedaddr, 16)
                for extendedaddr in config.extended_addresses.keys()
            }

        if config.row["nwk_aux_srcaddr"] is not None:
            potential_sources.add(int(config.row["nwk_aux_srcaddr"], 16))
        if config.row["nwk_srcextendedaddr"] is not None:
            potential_sources.add(int(config.row["nwk_srcextendedaddr"], 16))
        if config.row["mac_srcextendedaddr"] is not None:
            potential_sources.add(int(config.row["mac_srcextendedaddr"], 16))
    else:
        config.row["error_msg"] = "Invalid APS EN state"
        return

    # Key Sequence Number field (0/1 byte)
    if config.row["aps_aux_keytype"].startswith("0b01:"):
        config.row["aps_aux_keyseqnum"] = pkt[ZigbeeSecurityHeader].key_seqnum
        key_seqnum = pkt[ZigbeeSecurityHeader].key_seqnum
        potential_keys = config.network_keys.values()
    elif config.row["aps_aux_keytype"].startswith("0b00:"):
        key_seqnum = None
        potential_keys = config.link_keys.values()
    elif config.row["aps_aux_keytype"].startswith("0b10:"):
        key_seqnum = None
        potential_keys = {
            crypto.zigbee_hmac(bytes.fromhex("00"), key)
            for key in config.link_keys.values()
        }
    elif config.row["aps_aux_keytype"].startswith("0b11:"):
        key_seqnum = None
        potential_keys = {
            crypto.zigbee_hmac(bytes.fromhex("02"), key)
            for key in config.link_keys.values()
        }
    else:
        config.row["error_msg"] = "Invalid APS key type"
        return

    # Attempt to decrypt the payload
    if tunneled:
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
                config.row["aps_aux_deckey"] = key.hex()
                config.row["aps_aux_decsrc"] = format(source_addr, "016x")
                config.row["aps_aux_decpayload"] = dec_payload.hex()

                # APS Payload field (variable)
                if config.row["aps_frametype"].startswith("0b00:"):
                    if config.row["aps_profile_id"].startswith("0x0000:"):
                        dec_pkt = ZigbeeDeviceProfile(dec_payload)
                        config.row["aps_aux_decshow"] = dec_pkt.show(
                            dump=True,
                        )
                        zdp_fields(dec_pkt)
                        return
                    elif config.row["aps_profile_id"].split()[1] != "Unknown":
                        dec_pkt = ZigbeeClusterLibrary(dec_payload)
                        config.row["aps_aux_decshow"] = dec_pkt.show(
                            dump=True,
                        )
                        zcl_fields(dec_pkt)
                        return
                    else:
                        config.row["error_msg"] = (
                            "Unknown APS profile with ID {}".format(
                                config.row["aps_profile_id"],
                            )
                        )
                        return
                elif config.row["aps_frametype"].startswith("0b10:"):
                    # APS Acknowledgments do not contain any other fields
                    if len(dec_payload) != 0:
                        config.row["error_msg"] = "PE427: Unexpected payload"
                        return
                    return
                elif config.row["aps_frametype"].startswith("0b01:"):
                    dec_pkt = ZigbeeAppCommandPayload(dec_payload)
                    config.row["aps_aux_decshow"] = dec_pkt.show(dump=True)
                    aps_command_payload(dec_pkt, msg_queue, tunneled=tunneled)
                    return
                else:
                    config.row["error_msg"] = (
                        "Unexpected format of the decrypted APS payload"
                    )
                    return
    msg_obj = (
        "Unable to decrypt with a {} ".format(config.row["aps_aux_keytype"])
        + "the APS payload of packet #{} ".format(config.row["pkt_num"])
        + "in {}".format(config.row["pcap_filename"])
    )
    if msg_queue is None:
        logging.debug(msg_obj)
    else:
        msg_queue.put((Message.DEBUG, msg_obj))
    config.row["warning_msg"] = "PW401: Unable to decrypt the APS payload"


def aps_command_payload(pkt, msg_queue, tunneled=False):
    # Check whether this is a tunneled command or not
    if tunneled:
        cmd_id_column = "aps_tunnel_cmd_id"
    else:
        cmd_id_column = "aps_cmd_id"

    # Command Identifier field (1 byte)
    if not (
        config.update_row(
            cmd_id_column,
            pkt[ZigbeeAppCommandPayload].cmd_identifier,
            APS_COMMANDS,
            "PE412: Unknown APS command",
        )
    ):
        return

    # Command Payload field (variable)
    if config.row[cmd_id_column].startswith("0x05:"):
        aps_transportkey(pkt, msg_queue)
    elif config.row[cmd_id_column].startswith("0x06:"):
        aps_updatedevice(pkt)
    elif config.row[cmd_id_column].startswith("0x07:"):
        aps_removedevice(pkt)
    elif config.row[cmd_id_column].startswith("0x08:"):
        aps_requestkey(pkt)
    elif config.row[cmd_id_column].startswith("0x09:"):
        aps_switchkey(pkt)
    elif config.row[cmd_id_column].startswith("0x0e:"):
        aps_tunnel(pkt, msg_queue)
    elif config.row[cmd_id_column].startswith("0x0f:"):
        aps_verifykey(pkt)
    elif config.row[cmd_id_column].startswith("0x10:"):
        aps_confirmkey(pkt)
    else:
        config.row["error_msg"] = "Invalid APS command"
        return


def aps_transportkey(pkt, msg_queue):
    # Standard Key Type field (1 byte)
    if not (
        config.update_row(
            "aps_transportkey_stdkeytype",
            pkt[ZigbeeAppCommandPayload].key_type,
            STANDARD_KEY_TYPES,
            "PE413: Unknown standard key type",
        )
    ):
        return

    # Key Descriptor field (25/32/33 bytes)
    if config.row["aps_transportkey_stdkeytype"].startswith("0x01:"):
        # Key field (16 bytes)
        config.row["aps_transportkey_key"] = (
            pkt[ZigbeeAppCommandPayload].key.hex()
        )

        # Key Sequence Number field (1 byte)
        config.row["aps_transportkey_keyseqnum"] = (
            pkt[ZigbeeAppCommandPayload].key_seqnum
        )

        # Destination Extended Address field (8 bytes)
        config.row["aps_transportkey_dstextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].dest_addr,
            "016x",
        )

        # Source Extended Address field (8 bytes)
        config.row["aps_transportkey_srcextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].src_addr,
            "016x",
        )

        # Store the sniffed network key
        key_bytes = pkt[ZigbeeAppCommandPayload].key
        key_type = "network"
        key_name = "_sniffed_{}_{}".format(
            os.path.join(
                config.row["pcap_directory"],
                config.row["pcap_filename"],
            ),
            config.row["pkt_num"],
        )
        return_msg = config.add_new_key(key_bytes, key_type, key_name)
        if return_msg is not None:
            if msg_queue is None:
                logging.warning(return_msg)
            else:
                msg_queue.put((Message.WARNING, return_msg))
    elif config.row["aps_transportkey_stdkeytype"].startswith("0x04:"):
        # Key field (16 bytes)
        config.row["aps_transportkey_key"] = (
            pkt[ZigbeeAppCommandPayload].key.hex()
        )

        # Destination Extended Address field (8 bytes)
        config.row["aps_transportkey_dstextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].dest_addr,
            "016x",
        )

        # Source Extended Address field (8 bytes)
        config.row["aps_transportkey_srcextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].src_addr,
            "016x",
        )

        # Store the sniffed link key
        key_bytes = pkt[ZigbeeAppCommandPayload].key
        key_type = "link"
        key_name = "_sniffed_{}_{}".format(
            os.path.join(
                config.row["pcap_directory"],
                config.row["pcap_filename"],
            ),
            config.row["pkt_num"],
        )
        return_msg = config.add_new_key(key_bytes, key_type, key_name)
        if return_msg is not None:
            if msg_queue is None:
                logging.warning(return_msg)
            else:
                msg_queue.put((Message.WARNING, return_msg))
    elif config.row["aps_transportkey_stdkeytype"].startswith("0x03:"):
        # Key field (16 bytes)
        config.row["aps_transportkey_key"] = (
            pkt[ZigbeeAppCommandPayload].key.hex()
        )

        # Partner Extended Address field (8 bytes)
        config.row["aps_transportkey_prtextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].partner_addr,
            "016x",
        )

        # Initiator Flag field (1 byte)
        if not (
            config.update_row(
                "aps_transportkey_initflag",
                pkt[ZigbeeAppCommandPayload].initiator_flag,
                IF_STATES,
                "PE414: Unknown IF state",
            )
        ):
            return

        # Store the sniffed link key
        key_bytes = pkt[ZigbeeAppCommandPayload].key
        key_type = "link"
        key_name = "_sniffed_{}_{}".format(
            os.path.join(
                config.row["pcap_directory"],
                config.row["pcap_filename"],
            ),
            config.row["pkt_num"],
        )
        return_msg = config.add_new_key(key_bytes, key_type, key_name)
        if return_msg is not None:
            if msg_queue is None:
                logging.warning(return_msg)
            else:
                msg_queue.put((Message.WARNING, return_msg))
    else:
        config.row["error_msg"] = "Invalid standard key type"
        return

    # APS Transport Key commands do not contain any other fields
    if len(bytes(pkt[ZigbeeAppCommandPayload].payload)) != 0:
        config.row["error_msg"] = "PE428: Unexpected payload"
        return


def aps_updatedevice(pkt):
    # Device Extended Address field (8 bytes)
    config.row["aps_updatedevice_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address,
        "016x",
    )

    # Device Short Address field (2 bytes)
    config.row["aps_updatedevice_shortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeAppCommandPayload].short_address,
    )

    # Status field (1 byte)
    if not (
        config.update_row(
            "aps_updatedevice_status",
            pkt[ZigbeeAppCommandPayload].update_status,
            UD_STATUSES,
            "PE415: Unknown UD status",
        )
    ):
        return

    # APS Update Device commands do not contain any other fields
    if len(bytes(pkt[ZigbeeAppCommandPayload].payload)) != 0:
        config.row["error_msg"] = "PE429: Unexpected payload"
        return


def aps_removedevice(pkt):
    # Target Extended Address field (8 bytes)
    config.row["aps_removedevice_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address,
        "016x",
    )

    # APS Remove Device commands do not contain any other fields
    if len(bytes(pkt[ZigbeeAppCommandPayload].payload)) != 0:
        config.row["error_msg"] = "PE430: Unexpected payload"
        return


def aps_requestkey(pkt):
    # Request Key Type field (1 byte)
    if not (
        config.update_row(
            "aps_requestkey_reqkeytype",
            pkt[ZigbeeAppCommandPayload].key_type,
            REQUEST_KEY_TYPES,
            "PE416: Unknown request key type",
        )
    ):
        return

    # Partner Extended Address field (0/8 bytes)
    if config.row["aps_requestkey_reqkeytype"].startswith("0x02:"):
        config.row["aps_requestkey_prtextendedaddr"] = format(
            pkt[ZigbeeAppCommandPayload].partner_addr,
            "016x",
        )
    elif not config.row["aps_requestkey_reqkeytype"].startswith("0x04:"):
        config.row["error_msg"] = "Invalid request key type"
        return

    # APS Request Key commands do not contain any other fields
    if len(bytes(pkt[ZigbeeAppCommandPayload].payload)) != 0:
        config.row["error_msg"] = "PE431: Unexpected payload"
        return


def aps_switchkey(pkt):
    # Key Sequence Number field (1 byte)
    config.row["aps_switchkey_keyseqnum"] = (
        pkt[ZigbeeAppCommandPayload].seqnum
    )

    # APS Switch Key commands do not contain any other fields
    if len(bytes(pkt[ZigbeeAppCommandPayload].payload)) != 0:
        config.row["error_msg"] = "PE432: Unexpected payload"
        return


def aps_tunnel(pkt, msg_queue):
    # Destination Extended Address field (8 bytes)
    config.row["aps_tunnel_dstextendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].dest_addr,
        "016x",
    )

    # Tunneled Frame Control field (1 byte)
    # Tunneled Frame Type subfield (2 bits)
    if not (
        config.update_row(
            "aps_tunnel_frametype",
            pkt[ZigbeeAppCommandPayload].aps_frametype,
            APS_FRAME_TYPES,
            "PE417: Unknown tunneled frame type",
        )
    ):
        return
    if not config.row["aps_tunnel_frametype"].startswith("0b01:"):
        config.row["error_msg"] = "Unexpected tunneled frame type"
        return
    # Tunneled Delivery Mode subfield (2 bits)
    if not (
        config.update_row(
            "aps_tunnel_delmode",
            pkt[ZigbeeAppCommandPayload].delivery_mode,
            APS_DELIVERY_MODES,
            "PE418: Unknown tunneled delivery mode",
        )
    ):
        return
    if not config.row["aps_tunnel_delmode"].startswith("0b00:"):
        config.row["error_msg"] = "Unexpected tunneled delivery mode"
        return
    # Tunneled ACK Format subfield (1 bit)
    if not (
        config.update_row(
            "aps_tunnel_ackformat",
            pkt[ZigbeeAppCommandPayload].frame_control.ack_format,
            APS_ACKFORMAT_STATES,
            "PE419: Unknown tunneled ACK format state",
        )
    ):
        return
    if not config.row["aps_tunnel_ackformat"].startswith("0b0:"):
        config.row["error_msg"] = "Unexpected tunneled ACK format state"
        return
    # Tunneled Security subfield (1 bit)
    if not (
        config.update_row(
            "aps_tunnel_security",
            pkt[ZigbeeAppCommandPayload].frame_control.security,
            APS_SECURITY_STATES,
            "PE420: Unknown tunneled security state",
        )
    ):
        return
    if not config.row["aps_tunnel_security"].startswith("0b1:"):
        config.row["error_msg"] = "Unexpected tunneled security state"
        return
    # Tunneled Acknowledgment Request subfield (1 bit)
    if not (
        config.update_row(
            "aps_tunnel_ackreq",
            pkt[ZigbeeAppCommandPayload].frame_control.ack_req,
            APS_AR_STATES,
            "PE421: Unknown tunneled AR state",
        )
    ):
        return
    # Tunneled Extended Header subfield (1 bit)
    if not (
        config.update_row(
            "aps_tunnel_exthdr",
            pkt[ZigbeeAppCommandPayload].frame_control.extended_hdr,
            APS_EH_STATES,
            "PE422: Unknown tunneled EH state",
        )
    ):
        return
    if not config.row["aps_tunnel_exthdr"].startswith("0b0:"):
        config.row["error_msg"] = "Unexpected tunneled EH state"
        return

    # Tunneled APS Counter field (1 byte)
    config.row["aps_tunnel_counter"] = pkt[ZigbeeAppCommandPayload].counter

    # Tunneled Auxiliary Header field (13 bytes)
    if config.row["aps_security"].startswith("0b1:"):
        config.row["error_msg"] = (
            "An APS Auxiliary Header was already processed"
        )
        return
    elif config.row["aps_security"].startswith("0b0:"):
        aps_auxiliary(pkt, msg_queue, tunneled=True)
    else:
        config.row["error_msg"] = "Invalid APS security state"
        return


def aps_verifykey(pkt):
    # Standard Key Type field (1 byte)
    if not (
        config.update_row(
            "aps_verifykey_stdkeytype",
            pkt[ZigbeeAppCommandPayload].key_type,
            STANDARD_KEY_TYPES,
            "PE423: Unknown standard key type",
        )
    ):
        return

    # Source Extended Address field (8 bytes)
    config.row["aps_verifykey_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address,
        "016x",
    )

    # Initiator Verify-Key Hash Value field (16 bytes)
    config.row["aps_verifykey_keyhash"] = (
        pkt[ZigbeeAppCommandPayload].key_hash.hex()
    )

    # APS Verify Key commands do not contain any other fields
    if len(bytes(pkt[ZigbeeAppCommandPayload].payload)) != 0:
        config.row["error_msg"] = "PE433: Unexpected payload"
        return


def aps_confirmkey(pkt):
    # Status field (1 byte)
    if not (
        config.update_row(
            "aps_confirmkey_status",
            pkt[ZigbeeAppCommandPayload].status,
            CONFIRM_STATUSES,
            "PE424: Unknown confirm status",
        )
    ):
        return

    # Standard Key Type field (1 byte)
    if not (
        config.update_row(
            "aps_confirmkey_stdkeytype",
            pkt[ZigbeeAppCommandPayload].key_type,
            STANDARD_KEY_TYPES,
            "PE425: Unknown standard key type",
        )
    ):
        return

    # Destination Extended Address field (8 bytes)
    config.row["aps_confirmkey_extendedaddr"] = format(
        pkt[ZigbeeAppCommandPayload].address,
        "016x",
    )

    # APS Confirm Key commands do not contain any other fields
    if len(bytes(pkt[ZigbeeAppCommandPayload].payload)) != 0:
        config.row["error_msg"] = "PE434: Unexpected payload"
        return
