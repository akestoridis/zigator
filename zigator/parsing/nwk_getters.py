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
from scapy.all import ZigbeeNWK
from scapy.all import ZigbeeNWKCommandPayload
from scapy.all import ZigbeeSecurityHeader


def get_nwk_frametype(pkt):
    nwk_frame_types = {
        0: "NWK Data",
        1: "NWK Command",
        3: "NWK Inter-PAN"
    }
    frametype_id = pkt[ZigbeeNWK].frametype
    return nwk_frame_types.get(frametype_id, "Unknown NWK frame type")


def get_nwk_protocolversion(pkt):
    protocol_versions = {
        1: "Zigbee 2004",
        2: "Zigbee PRO",
        3: "Zigbee Green Power"
    }
    if pkt.haslayer(ZigbeeNWK):
        prot_ver = pkt[ZigbeeNWK].proto_version
    elif pkt.haslayer(ZigBeeBeacon):
        prot_ver = pkt[ZigBeeBeacon].nwkc_protocol_version
    else:
        prot_ver = None
    return protocol_versions.get(prot_ver, "Unknown NWK protocol version")


def get_nwk_discroute(pkt):
    discroute_states = {
        0: "Suppress route discovery",
        1: "Enable route discovery"
    }
    discroute_state = pkt[ZigbeeNWK].discover_route
    return discroute_states.get(discroute_state, "Unknown NWK DR state")


def get_nwk_aux_seclevel(pkt):
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
    return sec_levels.get(seclevel_id, "Unknown NWK security level")


def get_nwk_aux_keytype(pkt):
    key_types = {
        0: "Data Key",
        1: "Network Key",
        2: "Key-Transport Key",
        3: "Key-Load Key"
    }
    keytype_id = pkt[ZigbeeSecurityHeader].key_type
    return key_types.get(keytype_id, "Unknown NWK key type")


def get_nwk_aux_extnonce(pkt):
    extnonce_states = {
        0: "The source address is not present",
        1: "The source address is present"
    }
    extnonce_state = pkt[ZigbeeSecurityHeader].extended_nonce
    return extnonce_states.get(extnonce_state, "Unknown NWK EN state")


def get_nwk_command(pkt):
    nwk_commands = {
        1: "NWK Route Request",
        2: "NWK Route Reply",
        3: "NWK Network Status",
        4: "NWK Leave",
        5: "NWK Route Record",
        6: "NWK Rejoin Request",
        7: "NWK Rejoin Response",
        8: "NWK Link Status",
        9: "NWK Network Report",
        10: "NWK Network Update",
        11: "NWK End Device Timeout Request",
        12: "NWK End Device Timeout Response"
    }
    command_id = pkt[ZigbeeNWKCommandPayload].cmd_identifier
    return nwk_commands.get(command_id, "Unknown NWK command")


def get_nwk_routerequest_mto(pkt):
    mto_values = {
        0: "Not a Many-to-One Route Request",
        1: "Many-to-One Route Request with Route Record support",
        2: "Many-to-One Route Request without Route Record support",
    }
    mto_id = pkt[ZigbeeNWKCommandPayload].many_to_one
    return mto_values.get(mto_id, "Unknown Many-to-One value")


def get_nwk_routerequest_ed(pkt):
    dst_states = {
        0: "The extended destination address is not present",
        1: "The extended destination address is present"
    }
    dst_state = pkt[ZigbeeNWKCommandPayload].dest_addr_bit
    return dst_states.get(dst_state, "Unknown Extended Destination state")


def get_nwk_routerequest_mc(pkt):
    mc_states = {
        0: "The destination address is not a Group ID",
        1: "The destination address is a Group ID"
    }
    mc_state = pkt[ZigbeeNWKCommandPayload].multicast
    return mc_states.get(mc_state, "Unknown Multicast state")


def get_nwk_routereply_eo(pkt):
    dst_states = {
        0: "The extended originator address is not present",
        1: "The extended originator address is present"
    }
    dst_state = pkt[ZigbeeNWKCommandPayload].originator_addr_bit
    return dst_states.get(dst_state, "Unknown Extended Originator state")


def get_nwk_routereply_er(pkt):
    dst_states = {
        0: "The extended responder address is not present",
        1: "The extended responder address is present"
    }
    dst_state = pkt[ZigbeeNWKCommandPayload].responder_addr_bit
    return dst_states.get(dst_state, "Unknown Extended Responder state")


def get_nwk_routereply_mc(pkt):
    mc_states = {
        0: "The responder address is not a Group ID",
        1: "The responder address is a Group ID"
    }
    mc_state = pkt[ZigbeeNWKCommandPayload].multicast
    return mc_states.get(mc_state, "Unknown Multicast state")


def get_nwk_networkstatus_code(pkt):
    status_codes = {
        0: "No route available",
        1: "Tree link failure",
        2: "Non-tree link failure",
        3: "Low battery level",
        4: "No routing capacity",
        5: "No indirect capacity",
        6: "Indirect transaction expiry",
        7: "Target device unavailable",
        8: "Target address unallocated",
        9: "Parent link failure",
        10: "Validate route",
        11: "Source route failure",
        12: "Many-to-one route failure",
        13: "Address conflict",
        14: "Verify addresses",
        15: "PAN identifier update",
        16: "Network address update",
        17: "Bad frame counter",
        18: "Bad key sequence number"
    }
    status_code = pkt[ZigbeeNWKCommandPayload].status_code
    return status_codes.get(status_code, "Unknown Status Code value")


def get_nwk_leave_rejoin(pkt):
    rejoin_states = {
        0: "The device will not rejoin the network",
        1: "The device will rejoin the network"
    }
    rejoin_state = pkt[ZigbeeNWKCommandPayload].rejoin
    return rejoin_states.get(rejoin_state, "Unknown Rejoin state")


def get_nwk_leave_request(pkt):
    request_states = {
        0: "The sending device wants to leave the network",
        1: "Another device wants to leave the network"
    }
    request_state = pkt[ZigbeeNWKCommandPayload].request
    return request_states.get(request_state, "Unknown Request state")


def get_nwk_leave_rmch(pkt):
    rmch_states = {
        0: "The device's children will not be removed from the network",
        1: "The device's children will be removed from the network"
    }
    rmch_state = pkt[ZigbeeNWKCommandPayload].remove_children
    return rmch_states.get(rmch_state, "Unknown Remove Children state")


def get_nwk_rejoinreq_apc(pkt):
    apc_states = {
        0: "The sender is not capable of becoming a PAN coordinator",
        1: "The sender is capable of becoming a PAN coordinator"
    }
    apc_state = pkt[ZigbeeNWKCommandPayload].alternate_pan_coordinator
    return apc_states.get(apc_state, "Unknown APC state")


def get_nwk_rejoinreq_devtype(pkt):
    device_types = {
        0: "Zigbee End Device",
        1: "Zigbee Router"
    }
    devtype_id = pkt[ZigbeeNWKCommandPayload].device_type
    return device_types.get(devtype_id, "Unknown device type")


def get_nwk_rejoinreq_powsrc(pkt):
    power_sources = {
        0: "The sender is not a mains-powered device",
        1: "The sender is a mains-powered device"
    }
    pwrsrc_id = pkt[ZigbeeNWKCommandPayload].power_source
    return power_sources.get(pwrsrc_id, "Unknown power source")


def get_nwk_rejoinreq_rxidle(pkt):
    rxidle_states = {
        0: "Disables the receiver to conserve power when idle",
        1: "Does not disable the receiver to conserve power"
    }
    rxidle_state = pkt[ZigbeeNWKCommandPayload].receiver_on_when_idle
    return rxidle_states.get(rxidle_state, "Unknown RX state when idle")


def get_nwk_rejoinreq_seccap(pkt):
    seccap_states = {
        0: "Cannot transmit and receive secure MAC frames",
        1: "Can transmit and receive secure MAC frames"
    }
    seccap_state = pkt[ZigbeeNWKCommandPayload].security_capability
    return seccap_states.get(seccap_state, "Unknown MAC security capacity")


def get_nwk_rejoinreq_allocaddr(pkt):
    allocaddr_states = {
        0: "Does not request a short address",
        1: "Requests a short address"
    }
    allocaddr_state = pkt[ZigbeeNWKCommandPayload].allocate_address
    return allocaddr_states.get(allocaddr_state, "Unknown address allocation")


def get_nwk_rejoinrsp_status(pkt):
    rejoin_statuses = {
        0: "Rejoin successful",
        1: "PAN at capacity",
        2: "PAN access denied"
    }
    rejoin_status = pkt[ZigbeeNWKCommandPayload].rejoin_status
    return rejoin_statuses.get(rejoin_status, "Unknown rejoin status")


def get_nwk_linkstatus_first(pkt):
    first_statuses = {
        0: "This is not the first frame of the sender's link status",
        1: "This is the first frame of the sender's link status"
    }
    first_status = pkt[ZigbeeNWKCommandPayload].first_frame
    return first_statuses.get(first_status, "Unknown first frame status")


def get_nwk_linkstatus_last(pkt):
    last_statuses = {
        0: "This is not the last frame of the sender's link status",
        1: "This is the last frame of the sender's link status"
    }
    last_status = pkt[ZigbeeNWKCommandPayload].last_frame
    return last_statuses.get(last_status, "Unknown last frame status")


def get_nwk_networkreport_type(pkt):
    report_types = {
        0: "PAN Identifier Conflict"
    }
    report_type = pkt[ZigbeeNWKCommandPayload].report_command_identifier
    return report_types.get(report_type, "Unknown report type")


def get_nwk_networkupdate_type(pkt):
    update_types = {
        0: "PAN Identifier Update"
    }
    update_type = pkt[ZigbeeNWKCommandPayload].update_command_identifier
    return update_types.get(update_type, "Unknown update type")


def get_edtimeoutreq_reqtime(pkt):
    timeout_values = {
        0: "10 seconds",
        1: "2 minutes",
        2: "4 minutes",
        3: "8 minutes",
        4: "16 minutes",
        5: "32 minutes",
        6: "64 minutes",
        7: "128 minutes",
        8: "256 minutes",
        9: "512 minutes",
        10: "1024 minutes",
        11: "2048 minutes",
        12: "4096 minutes",
        13: "8192 minutes",
        14: "16384 minutes"
    }
    req_timeout = pkt[ZigbeeNWKCommandPayload].req_timeout
    return timeout_values.get(req_timeout, "Unknown requested timeout value")


def get_edtimeoutrsp_status(pkt):
    status_values = {
        0: "Success",
        1: "Incorrect Value"
    }
    status = pkt[ZigbeeNWKCommandPayload].status
    return status_values.get(status, "Unknown status value")


def get_edtimeoutrsp_poll(pkt):
    poll_states = {
        0: "MAC Data Poll Keepalive is not supported",
        1: "MAC Data Poll Keepalive is supported"
    }
    poll_state = pkt[ZigbeeNWKCommandPayload].mac_data_poll_keepalive
    return poll_states.get(poll_state, "Unknown poll state")


def get_edtimeoutrsp_timeout(pkt):
    timeout_states = {
        0: "End Device Timeout Request Keepalive is not supported",
        1: "End Device Timeout Request Keepalive is supported"
    }
    timeout_state = pkt[ZigbeeNWKCommandPayload].ed_timeout_req_keepalive
    return timeout_states.get(timeout_state, "Unknown timeout state")


def get_nwk_beacon_routercap(pkt):
    rcap_states = {
        0: "The sender cannot accept join requests from routers",
        1: "The sender can accept join requests from routers"
    }
    rcap_state = pkt[ZigBeeBeacon].router_capacity
    return rcap_states.get(rcap_state, "Unknown Router Capacity state")


def get_nwk_beacon_edcap(pkt):
    edcap_states = {
        0: "The sender cannot accept join requests from end devices",
        1: "The sender can accept join requests from end devices"
    }
    edcap_state = pkt[ZigBeeBeacon].end_device_capacity
    return edcap_states.get(edcap_state, "Unknown End Device Capacity state")
