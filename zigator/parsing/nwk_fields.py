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

import binascii
import logging

from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigBeeBeacon
from scapy.all import ZigbeeNWK
from scapy.all import ZigbeeNWKCommandPayload
from scapy.all import ZigbeeSecurityHeader

from .. import config
from .. import crypto
from .aps_fields import aps_fields


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
        0: "The sender is capable of becoming a PAN coordinator",
        1: "The sender is not capable of becoming a PAN coordinator"
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


def nwk_routerequest(pkt):
    # Command Options field (1 byte)
    config.entry["nwk_routerequest_mto"] = get_nwk_routerequest_mto(pkt)
    config.entry["nwk_routerequest_ed"] = get_nwk_routerequest_ed(pkt)
    config.entry["nwk_routerequest_mc"] = get_nwk_routerequest_mc(pkt)

    # Route Request Identifier field (1 byte)
    config.entry["nwk_routerequest_id"] = (
        pkt[ZigbeeNWKCommandPayload].route_request_identifier
    )

    # Short Destination Address field (2 bytes)
    config.entry["nwk_routerequest_dstshortaddr"] = hex(
        pkt[ZigbeeNWKCommandPayload].destination_address)

    # Path Cost field (1 byte)
    config.entry["nwk_routerequest_pathcost"] = (
        pkt[ZigbeeNWKCommandPayload].path_cost
    )

    # Extended Destination Address field (0/8 bytes)
    if (config.entry["nwk_routerequest_ed"]
            == "The extended destination address is present"):
        config.entry["nwk_routerequest_dstextendedaddr"] = hex(
            pkt[ZigbeeNWKCommandPayload].ext_dst)
    elif (config.entry["nwk_routerequest_ed"]
            != "The extended destination address is not present"):
        config.entry["error_msg"] = "Unknown Extended Destination state"

    return


def nwk_routereply(pkt):
    # Command Options field (1 byte)
    config.entry["nwk_routereply_eo"] = get_nwk_routereply_eo(pkt)
    config.entry["nwk_routereply_er"] = get_nwk_routereply_er(pkt)
    config.entry["nwk_routereply_mc"] = get_nwk_routereply_mc(pkt)

    # Route Request Identifier field (1 byte)
    config.entry["nwk_routereply_id"] = (
        pkt[ZigbeeNWKCommandPayload].route_request_identifier
    )

    # Originator Short Address field (2 bytes)
    config.entry["nwk_routereply_origshortaddr"] = hex(
        pkt[ZigbeeNWKCommandPayload].originator_address)

    # Responder Short Address field (2 bytes)
    config.entry["nwk_routereply_respshortaddr"] = hex(
        pkt[ZigbeeNWKCommandPayload].responder_address)

    # Path Cost field (1 byte)
    config.entry["nwk_routereply_pathcost"] = (
        pkt[ZigbeeNWKCommandPayload].path_cost
    )

    # Originator Extended Address field (0/8 bytes)
    if (config.entry["nwk_routereply_eo"]
            == "The extended originator address is present"):
        config.entry["nwk_routereply_origextendedaddr"] = hex(
            pkt[ZigbeeNWKCommandPayload].originator_addr)
    elif (config.entry["nwk_routereply_eo"]
            != "The extended originator address is not present"):
        config.entry["error_msg"] = "Unknown Extended Originator state"

    # Responder Extended Address field (0/8 bytes)
    if (config.entry["nwk_routereply_er"]
            == "The extended responder address is present"):
        config.entry["nwk_routereply_respextendedaddr"] = hex(
            pkt[ZigbeeNWKCommandPayload].responder_addr)
    elif (config.entry["nwk_routereply_er"]
            != "Unknown Extended Responder state"):
        config.entry["error_msg"] = "Unknown Extended Responder state"

    return


def nwk_networkstatus(pkt):
    # Status Code field (1 byte)
    config.entry["nwk_networkstatus_code"] = get_nwk_networkstatus_code(pkt)

    # Short Destination Address field (2 bytes)
    config.entry["nwk_networkstatus_dstshortaddr"] = hex(
        pkt[ZigbeeNWKCommandPayload].destination_address)

    return


def nwk_leave(pkt):
    # Command Options field (1 byte)
    config.entry["nwk_leave_rejoin"] = get_nwk_leave_rejoin(pkt)
    config.entry["nwk_leave_request"] = get_nwk_leave_request(pkt)
    config.entry["nwk_leave_rmch"] = get_nwk_leave_rmch(pkt)

    return


def nwk_routerecord(pkt):
    # Relay Count field (1 byte)
    config.entry["nwk_routerecord_relaycount"] = (
        pkt[ZigbeeNWKCommandPayload].rr_relay_count
    )

    # Relay List field (variable)
    config.entry["nwk_routerecord_relaylist"] = ",".join(
        "0x{:04X}".format(addr)
        for addr in pkt[ZigbeeNWKCommandPayload].rr_relay_list)

    return


def nwk_rejoinreq(pkt):
    # Capability Information field (1 byte)
    config.entry["nwk_rejoinreq_apc"] = get_nwk_rejoinreq_apc(pkt)
    config.entry["nwk_rejoinreq_devtype"] = get_nwk_rejoinreq_devtype(pkt)
    config.entry["nwk_rejoinreq_powsrc"] = get_nwk_rejoinreq_powsrc(pkt)
    config.entry["nwk_rejoinreq_rxidle"] = get_nwk_rejoinreq_rxidle(pkt)
    config.entry["nwk_rejoinreq_seccap"] = get_nwk_rejoinreq_seccap(pkt)
    config.entry["nwk_rejoinreq_allocaddr"] = get_nwk_rejoinreq_allocaddr(pkt)

    return


def nwk_rejoinrsp(pkt):
    # Network Address field (2 bytes)
    config.entry["nwk_rejoinrsp_shortaddr"] = hex(
        pkt[ZigbeeNWKCommandPayload].network_address)

    # Rejoin Status field (1 byte)
    config.entry["nwk_rejoinrsp_status"] = get_nwk_rejoinrsp_status(pkt)

    return


def nwk_linkstatus(pkt):
    # Command Options field (1 byte)
    config.entry["nwk_linkstatus_count"] = (
        pkt[ZigbeeNWKCommandPayload].entry_count
    )
    config.entry["nwk_linkstatus_first"] = get_nwk_linkstatus_first(pkt)
    config.entry["nwk_linkstatus_last"] = get_nwk_linkstatus_last(pkt)

    # Link Status List field (variable)
    linkstatus_list = pkt[ZigbeeNWKCommandPayload].link_status_list
    if config.entry["nwk_linkstatus_count"] != len(linkstatus_list):
        logging.debug("Packet #{} in {} contains {} link status entries "
                      "but read only {} link status entries"
                      "".format(config.entry["pkt_num"],
                                config.entry["pcap_filename"],
                                config.entry["nwk_linkstatus_count"],
                                len(linkstatus_list)))
        config.entry["error_msg"] = "Unable to process the Link Status List"
        return
    if config.entry["nwk_linkstatus_count"] > 0:
        config.entry["nwk_linkstatus_addresses"] = ",".join(
            hex(link.neighbor_network_address) for link in linkstatus_list)
        config.entry["nwk_linkstatus_incomingcosts"] = ",".join(
            str(link.incoming_cost) for link in linkstatus_list)
        config.entry["nwk_linkstatus_outgoingcosts"] = ",".join(
            str(link.outgoing_cost) for link in linkstatus_list)

    return


def nwk_networkreport(pkt):
    # Command Options field (1 byte)
    config.entry["nwk_networkreport_count"] = (
        pkt[ZigbeeNWKCommandPayload].report_information_count
    )
    config.entry["nwk_networkreport_type"] = get_nwk_networkreport_type(pkt)

    # EPID field (8 bytes)
    config.entry["nwk_networkreport_epid"] = hex(
        pkt[ZigbeeNWKCommandPayload].epid)

    # Report Information field (variable)
    if config.entry["nwk_networkreport_type"] == "PAN Identifier Conflict":
        panid_list = pkt[ZigbeeNWKCommandPayload].PAN_ID_conflict_report
        if config.entry["nwk_networkreport_count"] != len(panid_list):
            logging.debug("Packet #{} in {} contains {} PAN identifiers "
                          "but read only {} PAN identifiers"
                          "".format(config.entry["pkt_num"],
                                    config.entry["pcap_filename"],
                                    config.entry["nwk_network_count"],
                                    len(panid_list)))
            config.entry["error_msg"] = "Unable to process the PAN IDs"
            return
        if config.entry["nwk_networkreport_count"] > 0:
            config.entry["nwk_networkreport_info"] = ",".join(
                hex(panid) for panid in panid_list)
        return
    else:
        config.entry["error_msg"] = "Unknown report type"
        return


def nwk_networkupdate(pkt):
    # Command Options field (1 byte)
    config.entry["nwk_networkupdate_count"] = (
        pkt[ZigbeeNWKCommandPayload].update_information_count
    )
    config.entry["nwk_networkupdate_type"] = get_nwk_networkupdate_type(pkt)

    # EPID field (8 bytes)
    config.entry["nwk_networkupdate_epid"] = hex(
        pkt[ZigbeeNWKCommandPayload].epid)

    # Update ID field (1 byte)
    config.entry["nwk_networkupdate_updateid"] = (
        pkt[ZigbeeNWKCommandPayload].update_id
    )

    # Update Information field (variable)
    if config.entry["nwk_networkupdate_type"] == "PAN Identifier Update":
        # New PAN ID (2 bytes)
        config.entry["nwk_networkupdate_newpanid"] = hex(
            pkt[ZigbeeNWKCommandPayload].new_PAN_ID)
        return
    else:
        config.entry["error_msg"] = "Unknown update type"
        return


def nwk_edtimeoutreq(pkt):
    # Requested Timeout field (1 byte)
    config.entry["nwk_edtimeoutreq_reqtime"] = get_edtimeoutreq_reqtime(pkt)

    # End Device Configuration field (1 byte)
    config.entry["nwk_edtimeoutreq_edconf"] = (
        pkt[ZigbeeNWKCommandPayload].ed_conf
    )

    return


def nwk_edtimeoutrsp(pkt):
    # Status field (1 byte)
    config.entry["nwk_edtimeoutrsp_status"] = get_edtimeoutrsp_status(pkt)

    # Parent Information field (1 byte)
    config.entry["nwk_edtimeoutrsp_poll"] = get_edtimeoutrsp_poll(pkt)
    config.entry["nwk_edtimeoutrsp_timeout"] = get_edtimeoutrsp_timeout(pkt)

    return


def nwk_command(pkt):
    # Command Identifier field (1 byte)
    config.entry["nwk_cmd_id"] = get_nwk_command(pkt)

    # Command Payload field (variable)
    if config.entry["nwk_cmd_id"] == "NWK Route Request":
        nwk_routerequest(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Route Reply":
        nwk_routereply(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Network Status":
        nwk_networkstatus(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Leave":
        nwk_leave(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Route Record":
        nwk_routerecord(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Rejoin Request":
        nwk_rejoinreq(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Rejoin Response":
        nwk_rejoinrsp(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Link Status":
        nwk_linkstatus(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Network Report":
        nwk_networkreport(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Network Update":
        nwk_networkupdate(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK End Device Timeout Request":
        nwk_edtimeoutreq(pkt)
        return
    elif config.entry["nwk_cmd_id"] == "NWK End Device Timeout Response":
        nwk_edtimeoutrsp(pkt)
        return
    else:
        config.entry["error_msg"] = "Unknown NWK command"
        return


def nwk_beacon(pkt):
    # Beacon Payload field (15 bytes)
    config.entry["nwk_beacon_protocolid"] = pkt[ZigBeeBeacon].proto_id
    config.entry["nwk_beacon_stackprofile"] = pkt[ZigBeeBeacon].stack_profile
    config.entry["nwk_beacon_protocolversion"] = get_nwk_protocolversion(pkt)
    config.entry["nwk_beacon_routercap"] = pkt[ZigBeeBeacon].router_capacity
    config.entry["nwk_beacon_devdepth"] = pkt[ZigBeeBeacon].device_depth
    config.entry["nwk_beacon_edcap"] = pkt[ZigBeeBeacon].end_device_capacity
    config.entry["nwk_beacon_epid"] = hex(pkt[ZigBeeBeacon].extended_pan_id)
    config.entry["nwk_beacon_txoffset"] = pkt[ZigBeeBeacon].tx_offset
    config.entry["nwk_beacon_updateid"] = pkt[ZigBeeBeacon].update_id

    return


def nwk_auxiliary(pkt):
    # Security Control field (1 byte)
    config.entry["nwk_aux_seclevel"] = get_nwk_aux_seclevel(pkt)
    config.entry["nwk_aux_keytype"] = get_nwk_aux_keytype(pkt)
    config.entry["nwk_aux_extnonce"] = get_nwk_aux_extnonce(pkt)

    # Frame Counter field (4 bytes)
    config.entry["nwk_aux_framecounter"] = pkt[ZigbeeSecurityHeader].fc
    frame_counter = pkt[ZigbeeSecurityHeader].fc

    # Source Address field (0/8 bytes)
    if (config.entry["nwk_aux_extnonce"]
            == "The source address is present"):
        config.entry["nwk_aux_srcaddr"] = hex(
            pkt[ZigbeeSecurityHeader].source)
        potential_sources = set([pkt[ZigbeeSecurityHeader].source])
    elif (config.entry["nwk_aux_extnonce"]
            == "The source address is not present"):
        potential_sources = set()
        if config.entry["nwk_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["nwk_srcextendedaddr"], 16))
        if config.entry["mac_srcextendedaddr"] is not None:
            potential_sources.add(
                int(config.entry["mac_srcextendedaddr"], 16))
    else:
        config.entry["error_msg"] = "Unknown NWK EN state"
        return

    # Key Sequence Number field (1 byte)
    if config.entry["nwk_aux_keytype"] == "Network Key":
        config.entry["nwk_aux_keyseqnum"] = (
            pkt[ZigbeeSecurityHeader].key_seqnum
        )
        key_seqnum = pkt[ZigbeeSecurityHeader].key_seqnum
        potential_keys = config.network_keys.values()
    else:
        config.entry["error_msg"] = "Unexpected key type on the NWK layer"
        return

    # Attempt to decrypt the payload
    nwk_header = pkt[ZigbeeNWK].copy()
    nwk_header.remove_payload()
    header = raw(nwk_header)
    security_control = raw(pkt[ZigbeeSecurityHeader])[0]
    encrypted_payload = pkt[ZigbeeSecurityHeader].data[:-4]
    mic = pkt[ZigbeeSecurityHeader].data[-4:]
    for source_addr in potential_sources:
        for key in potential_keys:
            decrypted_payload, authentic_payload = crypto.decrypt_payload(
                key=key,
                source_addr=source_addr,
                frame_counter=frame_counter,
                security_control=security_control,
                header=header,
                key_seqnum=key_seqnum,
                encrypted_payload=encrypted_payload,
                mic=mic)
            if authentic_payload:
                config.entry["nwk_aux_decryptedpayload"] = binascii.hexlify(
                    decrypted_payload)
                if config.entry["nwk_frametype"] == "NWK Command":
                    nwk_command(ZigbeeNWKCommandPayload(decrypted_payload))
                    return
                elif config.entry["nwk_frametype"] == "NWK Data":
                    aps_fields(ZigbeeAppDataPayload(decrypted_payload))
                    return
                else:
                    config.entry["error_msg"] = (
                        "Unexpected format of decrypted NWK payload"
                    )
                    return

    logging.debug("Unable to decrypt the NWK payload of packet #{} in {}"
                  "".format(config.entry["pkt_num"],
                            config.entry["pcap_filename"]))
    config.entry["warning_msg"] = "Unable to decrypt the NWK payload"
    return


def nwk_fields(pkt):
    """Parse Zigbee NWK fields."""
    if config.entry["mac_frametype"] == "MAC Beacon":
        nwk_beacon(pkt)
        return
    elif config.entry["mac_frametype"] != "MAC Data":
        logging.debug("Packet #{} in {} contains unknown NWK fields"
                      "".format(config.entry["pkt_num"],
                                config.entry["pcap_filename"]))
        config.entry["error_msg"] = "Unknown NWK fields"
        return

    # Frame Control field (2 bytes)
    config.entry["nwk_frametype"] = get_nwk_frametype(pkt)
    config.entry["nwk_protocolversion"] = get_nwk_protocolversion(pkt)
    config.entry["nwk_discroute"] = get_nwk_discroute(pkt)
    if pkt[ZigbeeNWK].flags.multicast:
        config.entry["nwk_multicast"] = "NWK Multicast Enabled"
    else:
        config.entry["nwk_multicast"] = "NWK Multicast Disabled"
    if pkt[ZigbeeNWK].flags.security:
        config.entry["nwk_security"] = "NWK Security Enabled"
    else:
        config.entry["nwk_security"] = "NWK Security Disabled"
    if pkt[ZigbeeNWK].flags.source_route:
        config.entry["nwk_srcroute"] = "NWK Source Route Included"
    else:
        config.entry["nwk_srcroute"] = "NWK Source Route Omitted"
    if pkt[ZigbeeNWK].flags.extended_dst:
        config.entry["nwk_extendeddst"] = "NWK Extended Destination Included"
    else:
        config.entry["nwk_extendeddst"] = "NWK Extended Destination Omitted"
    if pkt[ZigbeeNWK].flags.extended_src:
        config.entry["nwk_extendedsrc"] = "NWK Extended Source Included"
    else:
        config.entry["nwk_extendedsrc"] = "NWK Extended Source Omitted"
    if pkt[ZigbeeNWK].flags.reserved1:
        config.entry["nwk_edinitiator"] = "NWK End Device Initiator"
    else:
        config.entry["nwk_edinitiator"] = "NWK Not End Device Initiator"

    # Short Destination Address field (2 bytes)
    config.entry["nwk_dstshortaddr"] = hex(pkt[ZigbeeNWK].destination)

    # Short Source Address field (2 bytes)
    config.entry["nwk_srcshortaddr"] = hex(pkt[ZigbeeNWK].source)

    # Radius field (1 byte)
    config.entry["nwk_radius"] = pkt[ZigbeeNWK].radius

    # Sequence Number field (1 byte)
    config.entry["nwk_seqnum"] = pkt[ZigbeeNWK].seqnum

    # Extended Destination Address field (0/8 bytes)
    if (config.entry["nwk_extendeddst"]
            == "NWK Extended Destination Included"):
        config.entry["nwk_dstextendedaddr"] = hex(pkt[ZigbeeNWK].ext_dst)
    elif (config.entry["nwk_extendeddst"]
            != "NWK Extended Destination Omitted"):
        config.entry["error_msg"] = "Unknown Extended Destination state"
        return

    # Extended Source Address field (0/8 bytes)
    if (config.entry["nwk_extendedsrc"]
            == "NWK Extended Source Included"):
        config.entry["nwk_srcextendedaddr"] = hex(pkt[ZigbeeNWK].ext_src)
    elif (config.entry["nwk_extendedsrc"]
            != "NWK Extended Source Omitted"):
        config.entry["error_msg"] = "Unknown Extended Source state"
        return

    # Multicast Control field (0/1 byte)
    if config.entry["nwk_multicast"] == "NWK Multicast Enabled":
        logging.debug("Packet #{} in {} contains a Multicast Control field "
                      "which could not be processed"
                      "".format(config.entry["pkt_num"],
                                config.entry["pcap_filename"]))
        config.entry["error_msg"] = "Could not process the Multicast Control"
        return
    elif config.entry["nwk_multicast"] != "NWK Multicast Disabled":
        config.entry["error_msg"] = "Unknown Multicast state"
        return

    # Source Route Subframe field (variable)
    if config.entry["nwk_srcroute"] == "NWK Source Route Included":
        config.entry["nwk_srcroute_relaycount"] = pkt[ZigbeeNWK].relay_count
        config.entry["nwk_srcroute_relayindex"] = pkt[ZigbeeNWK].relay_index
        config.entry["nwk_srcroute_relaylist"] = ",".join(
            "0x{:04X}".format(addr) for addr in pkt[ZigbeeNWK].relays)
    elif config.entry["nwk_srcroute"] != "NWK Source Route Omitted":
        config.entry["error_msg"] = "Unknown Source Route state"
        return

    if config.entry["nwk_security"] == "NWK Security Enabled":
        # NWK Auxiliary Header field (6/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            nwk_auxiliary(pkt)
            return
        else:
            config.entry["error_msg"] = (
                "The NWK Auxiliary Header is not included"
            )
            return
    elif config.entry["nwk_security"] == "NWK Security Disabled":
        # NWK Payload field (variable)
        if config.entry["nwk_frametype"] == "NWK Command":
            if pkt.haslayer(ZigbeeNWKCommandPayload):
                nwk_command(pkt)
                return
            else:
                config.entry["error_msg"] = "There are no NWK Command fields"
                return
        elif config.entry["nwk_frametype"] == "NWK Inter-PAN":
            logging.debug("Packet #{} in {} contains Inter-PAN fields"
                          "which were ignored"
                          "".format(config.entry["pkt_num"],
                                    config.entry["pcap_filename"]))
            config.entry["error_msg"] = "Ignored the Inter-PAN fields"
            return
        elif config.entry["nwk_frametype"] == "NWK Data":
            if pkt.haslayer(ZigbeeAppDataPayload):
                aps_fields(pkt)
                return
            else:
                config.entry["error_msg"] = "There are no Zigbee APS fields"
                return
        else:
            config.entry["error_msg"] = "Unknown NWK frame type"
            return
    else:
        config.entry["error_msg"] = "Unknown NWK security state"
        return
