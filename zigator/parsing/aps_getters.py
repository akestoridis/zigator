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

from scapy.all import ZigbeeAppCommandPayload
from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigbeeSecurityHeader


def get_aps_frametype(pkt):
    aps_frame_types = {
        0: "APS Data",
        1: "APS Command",
        2: "APS Acknowledgment",
        3: "APS Inter-PAN"
    }
    frametype_id = pkt[ZigbeeAppDataPayload].aps_frametype
    return aps_frame_types.get(frametype_id, "Unknown APS frame type")


def get_aps_delmode(pkt):
    aps_delivery_modes = {
        0: "Normal unicast delivery",
        2: "Broadcast",
        3: "Group addressing"
    }
    delmode_id = pkt[ZigbeeAppDataPayload].delivery_mode
    return aps_delivery_modes.get(delmode_id, "Unknown APS delivery mode")


def get_aps_fragmentation(pkt):
    aps_frag_state = {
        0: "No fragmentation",
        1: "First fragment",
        2: "Continued fragment"
    }
    frag_state = pkt[ZigbeeAppDataPayload].fragmentation
    return aps_frag_state.get(frag_state, "Unknown APS fragmentation")


def get_zdp_clustername(pkt):
    zdp_clusters = {
        0x0000: "NWK_addr_req",
        0x0001: "IEEE_addr_req",
        0x0002: "Node_Desc_req",
        0x0003: "Power_Desc_req",
        0x0004: "Simple_Desc_req",
        0x0005: "Active_EP_req",
        0x0006: "Match_Desc_req",
        0x0010: "Complex_Desc_req",
        0x0011: "User_Desc_req",
        0x0012: "Discovery_Cache_req",
        0x0013: "Device_annce",
        0x0014: "User_Desc_set",
        0x0015: "System_Server_Discovery_req",
        0x0016: "Discovery_store_req",
        0x0017: "Node_Desc_store_req",
        0x0018: "Power_Desc_store_req",
        0x0019: "Active_EP_store_req",
        0x001a: "Simple_Desc_store_req",
        0x001b: "Remove_node_cache_req",
        0x001c: "Find_node_cache_req",
        0x001d: "Extended_Simple_Desc_req",
        0x001e: "Extended_Active_EP_req",
        0x001f: "Parent_annce",
        0x0020: "End_Device_Bind_req",
        0x0021: "Bind_req",
        0x0022: "Unbind_req",
        0x0023: "Bind_Register_req",
        0x0024: "Replace_Device_req",
        0x0025: "Store_Bkup_Bind_Entry_req",
        0x0026: "Remove_Bkup_Bind_Entry_req",
        0x0027: "Backup_Bind_Table_req",
        0x0028: "Recover_Bind_Table_req",
        0x0029: "Backup_Source_Bind_req",
        0x002a: "Recover_Source_Bind_req",
        0x0030: "Mgmt_NWK_Disc_req",
        0x0031: "Mgmt_Lqi_req",
        0x0032: "Mgmt_Rtg_req",
        0x0033: "Mgmt_Bind_req",
        0x0034: "Mgmt_Leave_req",
        0x0035: "Mgmt_Direct_Join_req",
        0x0036: "Mgmt_Permit_Joining_req",
        0x0037: "Mgmt_Cache_req",
        0x0038: "Mgmt_NWK_Update_req",
        0x8000: "NWK_addr_rsp",
        0x8001: "IEEE_addr_rsp",
        0x8002: "Node_Desc_rsp",
        0x8003: "Power_Desc_rsp",
        0x8004: "Simple_Desc_rsp",
        0x8005: "Active_EP_rsp",
        0x8006: "Match_Desc_rsp",
        0x8010: "Complex_Desc_rsp",
        0x8011: "User_Desc_rsp",
        0x8012: "Discovery_Cache_rsp",
        0x8014: "User_Desc_conf",
        0x8015: "System_Server_Discovery_rsp",
        0x8016: "Discovery_store_rsp",
        0x8017: "Node_Desc_store_rsp",
        0x8018: "Power_Desc_store_rsp",
        0x8019: "Active_EP_store_rsp",
        0x801a: "Simple_Desc_store_rsp",
        0x801b: "Remove_node_cache_rsp",
        0x801c: "Find_node_cache_rsp",
        0x801d: "Extended_Simple_Desc_rsp",
        0x801e: "Extended_Active_EP_rsp",
        0x801f: "Parent_annce_rsp",
        0x8020: "End_Device_Bind_rsp",
        0x8021: "Bind_rsp",
        0x8022: "Unbind_rsp",
        0x8023: "Bind_Register_rsp",
        0x8024: "Replace_Device_rsp",
        0x8025: "Store_Bkup_Bind_Entry_rsp",
        0x8026: "Remove_Bkup_Bind_Entry_rsp",
        0x8027: "Backup_Bind_Table_rsp",
        0x8028: "Recover_Bind_Table_rsp",
        0x8029: "Backup_Source_Bind_rsp",
        0x802a: "Recover_Source_Bind_rsp",
        0x8030: "Mgmt_NWK_Disc_rsp",
        0x8031: "Mgmt_Lqi_rsp",
        0x8032: "Mgmt_Rtg_rsp",
        0x8033: "Mgmt_Bind_rsp",
        0x8034: "Mgmt_Leave_rsp",
        0x8035: "Mgmt_Direct_Join_rsp",
        0x8036: "Mgmt_Permit_Joining_rsp",
        0x8037: "Mgmt_Cache_rsp",
        0x8038: "Mgmt_NWK_Update_notify"
    }
    cluster_id = pkt[ZigbeeAppDataPayload].cluster
    return zdp_clusters.get(cluster_id, "Unknown ZDP cluster name")


def get_zcl_clustername(pkt):
    zcl_clusters = {
        0x0000: "Basic",
        0x0001: "Power Configuration",
        0x0002: "Device Temperature Configuration",
        0x0003: "Identify",
        0x0004: "Groups",
        0x0005: "Scenes",
        0x0006: "On/Off",
        0x0007: "On/Off Switch Configuration",
        0x0008: "Level Control",
        0x0009: "Alarms",
        0x000a: "Time",
        0x000b: "RSSI Location",
        0x000c: "Analog Input (basic)",
        0x000d: "Analog Output (basic)",
        0x000e: "Analog Value (basic)",
        0x000f: "Binary Input (basic)",
        0x0010: "Binary Output (basic)",
        0x0011: "Binary Value (basic)",
        0x0012: "Multistate Input (basic)",
        0x0013: "Multistate Output (basic)",
        0x0014: "Multistate Value (basic)",
        0x0015: "Commissioning",
        0x0016: "Partition",
        0x0019: "OTA Upgrade",
        0x001a: "Power Profile",
        0x001b: "EN50523 Appliance Control",
        0x0020: "Poll Control",
        0x0022: "Mobile Device Configuration Cluster",
        0x0023: "Neighbor Cleaning Cluster",
        0x0024: "Nearest Gateway Cluster",
        0x0100: "Shade Configuration",
        0x0101: "Door Lock",
        0x0102: "Window Covering",
        0x0200: "Pump Configuration and Control",
        0x0201: "Thermostat",
        0x0202: "Fan Control",
        0x0203: "Dehumidification Control",
        0x0204: "Thermostat User Interface Configuration",
        0x0300: "Color Control",
        0x0301: "Ballast Configuration",
        0x0400: "Illuminance Measurement",
        0x0401: "Illuminance Level Sensing",
        0x0402: "Temperature Measurement",
        0x0403: "Pressure Measurement",
        0x0404: "Flow Measurement",
        0x0405: "Relative Humidity Measurement",
        0x0406: "Occupancy Sensing",
        0x0500: "IAS Zone",
        0x0501: "IAS ACE",
        0x0502: "IAS WD",
        0x0600: "Generic Tunnel",
        0x0601: "BACnet Protocol Tunnel",
        0x0602: "Analog Input (BACnet regular)",
        0x0603: "Analog Input (BACnet extended)",
        0x0604: "Analog Output (BACnet regular)",
        0x0605: "Analog Output (BACnet extended)",
        0x0606: "Analog Value (BACnet regular)",
        0x0607: "Analog Value (BACnet extended)",
        0x0608: "Binary Input (BACnet regular)",
        0x0609: "Binary Input (BACnet extended)",
        0x060a: "Binary Output (BACnet regular)",
        0x060b: "Binary Output (BACnet extended)",
        0x060c: "Binary Value (BACnet regular)",
        0x060d: "Binary Value (BACnet extended)",
        0x060e: "Multistate Input (BACnet regular)",
        0x060f: "Multistate Input (BACnet extended)",
        0x0610: "Multistate Output (BACnet regular)",
        0x0611: "Multistate Output (BACnet extended)",
        0x0612: "Multistate Value (BACnet regular)",
        0x0613: "Multistate Value (BACnet extended)",
        0x0614: "11073 Protocol Tunnel",
        0x0615: "ISO7816 Tunnel",
        0x0617: "Retail Tunnel Cluster",
        0x0700: "Price",
        0x0701: "Demand Response and Local Control",
        0x0702: "Metering",
        0x0703: "Messaging",
        0x0704: "Tunneling",
        0x0800: "Key Establishment",
        0x0900: "Information",
        0x0904: "Voice over Zigbee",
        0x0905: "Chatting",
        0x0b00: "EN50523 Appliance Identification",
        0x0b01: "Meter Identification",
        0x0b02: "EN50523 Appliance Events and Alerts",
        0x0b03: "EN50523 Appliance Statistics",
        0x0b04: "Electrical Measurement",
        0x0b05: "Diagnostics",
        0x1000: "Touchlink"
    }
    cluster_id = pkt[ZigbeeAppDataPayload].cluster
    return zcl_clusters.get(cluster_id, "Unknown ZCL cluster name")


def get_aps_clustername(pkt):
    aps_profileid = pkt[ZigbeeAppDataPayload].profile
    aps_clusterid = pkt[ZigbeeAppDataPayload].cluster
    if aps_profileid == 0x0000:
        return get_zdp_clustername(pkt)
    elif aps_profileid > 0x0000 and aps_profileid <= 0x7fff:
        if aps_clusterid >= 0x0000 and aps_clusterid <= 0x7fff:
            return get_zcl_clustername(pkt)
        else:
            return "Unknown Manufacturer-Specific cluster name"
    else:
        return "Unknown APS cluster name"


def get_aps_profilename(pkt):
    aps_profiles = {
        0x0000: "Zigbee Device Profile (ZDP)",
        0x0104: "Zigbee Home Automation (ZHA)"
    }
    aps_profileid = pkt[ZigbeeAppDataPayload].profile
    if aps_profileid >= 0x0000 and aps_profileid <= 0x7fff:
        return aps_profiles.get(aps_profileid, "Unknown APS profile name")
    elif aps_profileid >= 0xc000 and aps_profileid <= 0xffff:
        return "Unknown Manufacturer-Specific profile name"
    else:
        return "Unknown APS profile name"


def get_aps_aux_seclevel(pkt):
    sec_levels = {
        0: "None",
        1: "MIC-32",
        2: "MIC-64",
        3: "MIC-128",
        4: "ENC",
        5: "ENC-MIC-32",
        6: "ENC-MIC-64",
        7: "ENC-MIC-128"
    }
    seclevel_id = pkt[ZigbeeSecurityHeader].nwk_seclevel
    return sec_levels.get(seclevel_id, "Unknown APS security level")


def get_aps_aux_keytype(pkt):
    key_types = {
        0: "Data Key",
        1: "Network Key",
        2: "Key-Transport Key",
        3: "Key-Load Key"
    }
    keytype_id = pkt[ZigbeeSecurityHeader].key_type
    return key_types.get(keytype_id, "Unknown APS key type")


def get_aps_aux_extnonce(pkt):
    extnonce_states = {
        0: "The source address is not present",
        1: "The source address is present"
    }
    extnonce_state = pkt[ZigbeeSecurityHeader].extended_nonce
    return extnonce_states.get(extnonce_state, "Unknown APS EN state")


def get_aps_command(pkt):
    aps_commands = {
        5: "APS Transport Key",
        6: "APS Update Device",
        7: "APS Remove Device",
        8: "APS Request Key",
        9: "APS Switch Key",
        14: "APS Tunnel",
        15: "APS Verify Key",
        16: "APS Confirm Key"
    }
    cmd_id = pkt[ZigbeeAppCommandPayload].cmd_identifier
    return aps_commands.get(cmd_id, "Unknown APS command")


def get_aps_stdkeytype(pkt):
    stdkey_types = {
        1: "Standard Network Key",
        3: "Application Link Key",
        4: "Trust Center Link Key"
    }
    stdkeytype_id = pkt[ZigbeeAppCommandPayload].key_type
    return stdkey_types.get(stdkeytype_id, "Unknown Standard Key Type value")


def get_aps_initflag(pkt):
    flag_values = {
        0: "The receiver did not request this key",
        1: "The receiver requested this key"
    }
    flag_value = pkt[ZigbeeAppCommandPayload].initiator_flag
    return flag_values.get(flag_value, "Unknown Initiator Flag value")


def get_aps_updatedevice_status(pkt):
    status_values = {
        0: "Standard device secured rejoin",
        1: "Standard device unsecured rejoin",
        2: "Device left",
        3: "Standard device trust center rejoin"
    }
    status_value = pkt[ZigbeeAppCommandPayload].status
    return status_values.get(status_value, "Unknown Status value")


def get_aps_reqkeytype(pkt):
    reqkey_types = {
        2: "Application Link Key",
        4: "Trust Center Link Key"
    }
    reqkeytype_id = pkt[ZigbeeAppCommandPayload].key_type
    return reqkey_types.get(reqkeytype_id, "Unknown Request Key Type value")


def get_aps_confirmkey_status(pkt):
    status_values = {
        0x00: "SUCCESS",
        0xa0: "ASDU_TOO_LONG",
        0xa1: "DEFRAG_DEFERRED",
        0xa2: "DEFRAG_UNSUPPORTED",
        0xa3: "ILLEGAL_REQUEST",
        0xa4: "INVALID_BINDING",
        0xa5: "INVALID_GROUP",
        0xa6: "INVALID_PARAMETER",
        0xa7: "NO_ACK",
        0xa8: "NO_BOUND_DEVICE",
        0xa9: "NO_SHORT_ADDRESS",
        0xaa: "NOT_SUPPORTED",
        0xab: "SECURED_LINK_KEY",
        0xac: "SECURED_NWK_KEY",
        0xad: "SECURITY_FAIL",
        0xae: "TABLE_FULL",
        0xaf: "UNSECURED",
        0xb0: "UNSUPPORTED_ATTRIBUTE"
    }
    status_value = pkt[ZigbeeAppCommandPayload].status
    return status_values.get(status_value, "Unknown Status value")
