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
from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigbeeNWK
from scapy.all import ZigbeeNWKCommandPayload
from scapy.all import ZigbeeSecurityHeader

from .. import config
from .. import crypto
from .aps_fields import aps_fields
from .nwk_getters import get_edtimeoutreq_reqtime
from .nwk_getters import get_edtimeoutrsp_poll
from .nwk_getters import get_edtimeoutrsp_status
from .nwk_getters import get_edtimeoutrsp_timeout
from .nwk_getters import get_nwk_aux_extnonce
from .nwk_getters import get_nwk_aux_keytype
from .nwk_getters import get_nwk_aux_seclevel
from .nwk_getters import get_nwk_beacon_edcap
from .nwk_getters import get_nwk_beacon_routercap
from .nwk_getters import get_nwk_command
from .nwk_getters import get_nwk_discroute
from .nwk_getters import get_nwk_frametype
from .nwk_getters import get_nwk_leave_rejoin
from .nwk_getters import get_nwk_leave_request
from .nwk_getters import get_nwk_leave_rmch
from .nwk_getters import get_nwk_linkstatus_first
from .nwk_getters import get_nwk_linkstatus_last
from .nwk_getters import get_nwk_networkreport_type
from .nwk_getters import get_nwk_networkstatus_code
from .nwk_getters import get_nwk_networkupdate_type
from .nwk_getters import get_nwk_protocolversion
from .nwk_getters import get_nwk_rejoinreq_allocaddr
from .nwk_getters import get_nwk_rejoinreq_apc
from .nwk_getters import get_nwk_rejoinreq_devtype
from .nwk_getters import get_nwk_rejoinreq_powsrc
from .nwk_getters import get_nwk_rejoinreq_rxidle
from .nwk_getters import get_nwk_rejoinreq_seccap
from .nwk_getters import get_nwk_rejoinrsp_status
from .nwk_getters import get_nwk_routereply_eo
from .nwk_getters import get_nwk_routereply_er
from .nwk_getters import get_nwk_routereply_mc
from .nwk_getters import get_nwk_routerequest_ed
from .nwk_getters import get_nwk_routerequest_mc
from .nwk_getters import get_nwk_routerequest_mto


def nwk_routerequest(pkt):
    # Command Options field (1 byte)
    config.entry["nwk_routerequest_mto"] = get_nwk_routerequest_mto(pkt)
    config.entry["nwk_routerequest_ed"] = get_nwk_routerequest_ed(pkt)
    config.entry["nwk_routerequest_mc"] = get_nwk_routerequest_mc(pkt)

    # Route Request Identifier field (1 byte)
    config.entry["nwk_routerequest_id"] = (
        pkt[ZigbeeNWKCommandPayload].route_request_identifier
    )

    # Destination Short Address field (2 bytes)
    config.entry["nwk_routerequest_dstshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].destination_address)

    # Path Cost field (1 byte)
    config.entry["nwk_routerequest_pathcost"] = (
        pkt[ZigbeeNWKCommandPayload].path_cost
    )

    # Destination Extended Address field (0/8 bytes)
    if (config.entry["nwk_routerequest_ed"]
            == "The extended destination address is present"):
        config.entry["nwk_routerequest_dstextendedaddr"] = format(
            pkt[ZigbeeNWKCommandPayload].ext_dst, "016x")
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
    config.entry["nwk_routereply_origshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].originator_address)

    # Responder Short Address field (2 bytes)
    config.entry["nwk_routereply_respshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].responder_address)

    # Path Cost field (1 byte)
    config.entry["nwk_routereply_pathcost"] = (
        pkt[ZigbeeNWKCommandPayload].path_cost
    )

    # Originator Extended Address field (0/8 bytes)
    if (config.entry["nwk_routereply_eo"]
            == "The extended originator address is present"):
        config.entry["nwk_routereply_origextendedaddr"] = format(
            pkt[ZigbeeNWKCommandPayload].originator_addr, "016x")
    elif (config.entry["nwk_routereply_eo"]
            != "The extended originator address is not present"):
        config.entry["error_msg"] = "Unknown Extended Originator state"

    # Responder Extended Address field (0/8 bytes)
    if (config.entry["nwk_routereply_er"]
            == "The extended responder address is present"):
        config.entry["nwk_routereply_respextendedaddr"] = format(
            pkt[ZigbeeNWKCommandPayload].responder_addr, "016x")
    elif (config.entry["nwk_routereply_er"]
            != "Unknown Extended Responder state"):
        config.entry["error_msg"] = "Unknown Extended Responder state"

    return


def nwk_networkstatus(pkt):
    # Status Code field (1 byte)
    config.entry["nwk_networkstatus_code"] = get_nwk_networkstatus_code(pkt)

    # Destination Short Address field (2 bytes)
    config.entry["nwk_networkstatus_dstshortaddr"] = "0x{:04x}".format(
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
        "0x{:04x}".format(addr)
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
    config.entry["nwk_rejoinrsp_shortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWKCommandPayload].network_address)

    # Rejoin Status field (1 byte)
    config.entry["nwk_rejoinrsp_status"] = get_nwk_rejoinrsp_status(pkt)

    return


def nwk_linkstatus(pkt, msg_queue):
    # Command Options field (1 byte)
    config.entry["nwk_linkstatus_count"] = (
        pkt[ZigbeeNWKCommandPayload].entry_count
    )
    config.entry["nwk_linkstatus_first"] = get_nwk_linkstatus_first(pkt)
    config.entry["nwk_linkstatus_last"] = get_nwk_linkstatus_last(pkt)

    # Link Status List field (variable)
    linkstatus_list = pkt[ZigbeeNWKCommandPayload].link_status_list
    if config.entry["nwk_linkstatus_count"] != len(linkstatus_list):
        msg_queue.put(
            (config.DEBUG_MSG,
             "Packet #{} in {} contains {} link status entries "
             "but read only {} link status entries"
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"],
                       config.entry["nwk_linkstatus_count"],
                       len(linkstatus_list))))
        config.entry["error_msg"] = "Unable to process the Link Status List"
        return
    if config.entry["nwk_linkstatus_count"] > 0:
        config.entry["nwk_linkstatus_addresses"] = ",".join("0x{:04x}".format(
            link.neighbor_network_address) for link in linkstatus_list)
        config.entry["nwk_linkstatus_incomingcosts"] = ",".join(
            str(link.incoming_cost) for link in linkstatus_list)
        config.entry["nwk_linkstatus_outgoingcosts"] = ",".join(
            str(link.outgoing_cost) for link in linkstatus_list)

    return


def nwk_networkreport(pkt, msg_queue):
    # Command Options field (1 byte)
    config.entry["nwk_networkreport_count"] = (
        pkt[ZigbeeNWKCommandPayload].report_information_count
    )
    config.entry["nwk_networkreport_type"] = get_nwk_networkreport_type(pkt)

    # EPID field (8 bytes)
    config.entry["nwk_networkreport_epid"] = format(
        pkt[ZigbeeNWKCommandPayload].epid, "016x")

    # Report Information field (variable)
    if config.entry["nwk_networkreport_type"] == "PAN Identifier Conflict":
        panid_list = pkt[ZigbeeNWKCommandPayload].PAN_ID_conflict_report
        if config.entry["nwk_networkreport_count"] != len(panid_list):
            msg_queue.put(
                (config.DEBUG_MSG,
                 "Packet #{} in {} contains {} PAN identifiers "
                 "but read only {} PAN identifiers"
                 "".format(config.entry["pkt_num"],
                           config.entry["pcap_filename"],
                           config.entry["nwk_network_count"],
                           len(panid_list))))
            config.entry["error_msg"] = "Unable to process the PAN IDs"
            return
        if config.entry["nwk_networkreport_count"] > 0:
            config.entry["nwk_networkreport_info"] = ",".join(
                "0x{:04x}".format(panid) for panid in panid_list)
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
    config.entry["nwk_networkupdate_epid"] = format(
        pkt[ZigbeeNWKCommandPayload].epid, "016x")

    # Update ID field (1 byte)
    config.entry["nwk_networkupdate_updateid"] = (
        pkt[ZigbeeNWKCommandPayload].update_id
    )

    # Update Information field (variable)
    if config.entry["nwk_networkupdate_type"] == "PAN Identifier Update":
        # New PAN ID (2 bytes)
        config.entry["nwk_networkupdate_newpanid"] = "0x{:04x}".format(
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


def nwk_command(pkt, msg_queue):
    # Command Identifier field (1 byte)
    config.entry["nwk_cmd_id"] = get_nwk_command(pkt)

    # Compute the NWK Command Payload Length
    # The constant 14 was derived by summing the following:
    #  2: MAC Frame Control
    #  1: MAC Sequence Number
    #  2: NWK Frame Control
    #  2: NWK Destination Short Address
    #  2: NWK Source Short Address
    #  1: NWK Radius
    #  1: NWK Sequence Number
    #  1: NWK Command Identifier
    #  2: MAC Frame Check Sequence
    config.entry["nwk_cmd_payloadlength"] = config.entry["phy_length"] - 14
    # Compute the length of the MAC Destination Addressing fields
    if (config.entry["mac_dstaddrmode"]
            == "Short destination MAC address"):
        config.entry["nwk_cmd_payloadlength"] -= 4
    elif (config.entry["mac_dstaddrmode"]
            == "Extended destination MAC address"):
        config.entry["nwk_cmd_payloadlength"] -= 10
    elif (config.entry["mac_dstaddrmode"]
            != "No destination MAC address"):
        config.entry["error_msg"] = "Unknown MAC DA mode"
        return
    # Compute the length of the MAC Source Addressing fields
    if (config.entry["mac_srcaddrmode"]
            == "Short source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["nwk_cmd_payloadlength"] -= 2
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["nwk_cmd_payloadlength"] -= 2
    elif (config.entry["mac_srcaddrmode"]
            == "Extended source MAC address"):
        if (config.entry["mac_panidcomp"]
                == "Do not compress the source PAN ID"):
            config.entry["nwk_cmd_payloadlength"] -= 2
        elif (config.entry["mac_panidcomp"]
                != "The source PAN ID is the same as the destination PAN ID"):
            config.entry["error_msg"] = "Unknown MAC PC state"
            return
        config.entry["nwk_cmd_payloadlength"] -= 8
    elif (config.entry["mac_srcaddrmode"]
            != "No source MAC address"):
        config.entry["error_msg"] = "Unknown MAC SA mode"
        return
    # Compute the length of the MAC Auxiliary Security Header field
    if config.entry["mac_security"] == "MAC Security Enabled":
        msg_queue.put(
            (config.DEBUG_MSG,
             "Ignored packet #{} in {} because it utilizes "
             "security services on the MAC layer"
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"])))
        config.entry["error_msg"] = (
            "Ignored NWK command with enabled MAC-layer security"
        )
        return
    elif config.entry["mac_security"] != "MAC Security Disabled":
        config.entry["error_msg"] = "Unknown MAC security state"
        return
    # Check for the presence of the Destination Extended Address field
    if (config.entry["nwk_extendeddst"]
            == "NWK Extended Destination Included"):
        config.entry["nwk_cmd_payloadlength"] -= 8
    elif (config.entry["nwk_extendeddst"]
            != "NWK Extended Destination Omitted"):
        config.entry["error_msg"] = "Unknown Extended Destination state"
        return
    # Check for the presence of the Source Extended Address field
    if (config.entry["nwk_extendedsrc"]
            == "NWK Extended Source Included"):
        config.entry["nwk_cmd_payloadlength"] -= 8
    elif (config.entry["nwk_extendedsrc"]
            != "NWK Extended Source Omitted"):
        config.entry["error_msg"] = "Unknown Extended Source state"
        return
    # Check for the presence of the Multicast Control field
    if config.entry["nwk_multicast"] == "NWK Multicast Enabled":
        msg_queue.put(
            (config.DEBUG_MSG,
             "Ignored packet #{} in {} because it contains "
             "a Multicast Control field "
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"])))
        config.entry["error_msg"] = (
            "Ignored NWK command that includes the Multicast Control field"
        )
        return
    elif config.entry["nwk_multicast"] != "NWK Multicast Disabled":
        config.entry["error_msg"] = "Unknown Multicast state"
        return
    # Check for the presence of the Source Route Subframe field
    if config.entry["nwk_srcroute"] == "NWK Source Route Included":
        config.entry["nwk_cmd_payloadlength"] -= (
            2 + 2*config.entry["nwk_srcroute_relaycount"]
        )
    elif config.entry["nwk_srcroute"] != "NWK Source Route Omitted":
        config.entry["error_msg"] = "Unknown Source Route state"
        return
    # Compute the length of the NWK Auxiliary Header field
    if config.entry["nwk_security"] == "NWK Security Enabled":
        config.entry["nwk_cmd_payloadlength"] -= 9
        if (config.entry["nwk_aux_extnonce"]
                == "The source address is present"):
            config.entry["nwk_cmd_payloadlength"] -= 8
        elif (config.entry["nwk_aux_extnonce"]
                != "The source address is not present"):
            config.entry["error_msg"] = "Unknown NWK EN state"
            return
        if config.entry["nwk_aux_keytype"] == "Network Key":
            config.entry["nwk_cmd_payloadlength"] -= 1
        else:
            config.entry["error_msg"] = "Unexpected key type on the NWK layer"
            return
    elif config.entry["nwk_security"] != "NWK Security Disabled":
        config.entry["error_msg"] = "Unknown NWK security state"
        return

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
        nwk_linkstatus(pkt, msg_queue)
        return
    elif config.entry["nwk_cmd_id"] == "NWK Network Report":
        nwk_networkreport(pkt, msg_queue)
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
    config.entry["nwk_beacon_routercap"] = get_nwk_beacon_routercap(pkt)
    config.entry["nwk_beacon_devdepth"] = pkt[ZigBeeBeacon].device_depth
    config.entry["nwk_beacon_edcap"] = get_nwk_beacon_edcap(pkt)
    config.entry["nwk_beacon_epid"] = format(
        pkt[ZigBeeBeacon].extended_pan_id, "016x")
    config.entry["nwk_beacon_txoffset"] = pkt[ZigBeeBeacon].tx_offset
    config.entry["nwk_beacon_updateid"] = pkt[ZigBeeBeacon].update_id

    return


def nwk_auxiliary(pkt, msg_queue):
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
        config.entry["nwk_aux_srcaddr"] = format(
            pkt[ZigbeeSecurityHeader].source, "016x")
        potential_sources = set([pkt[ZigbeeSecurityHeader].source])
    elif (config.entry["nwk_aux_extnonce"]
            == "The source address is not present"):
        potential_sources = set()
        shortaddr = config.entry["mac_srcshortaddr"]
        panid = config.entry["mac_dstpanid"]

        if (shortaddr, panid) in config.addresses:
            if config.addresses[(shortaddr, panid)] != "Conflicting Data":
                potential_sources.add(
                    int(config.addresses[(shortaddr, panid)], 16))
            else:
                potential_sources.update(
                    [int(extendedaddr, 16)
                     for extendedaddr in config.devices.keys()])
        else:
            potential_sources.update(
                [int(extendedaddr, 16)
                 for extendedaddr in config.devices.keys()])

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
    header = bytes(nwk_header)
    sec_control = bytes(pkt[ZigbeeSecurityHeader])[0]
    enc_payload = pkt[ZigbeeSecurityHeader].data[:-4]
    mic = pkt[ZigbeeSecurityHeader].data[-4:]
    for source_addr in potential_sources:
        for key in potential_keys:
            dec_payload, auth_payload = crypto.zigbee_dec_ver(
                key, source_addr, frame_counter, sec_control,
                header, key_seqnum, enc_payload, mic)

            # Check whether the decrypted payload is authentic
            if auth_payload:
                config.entry["nwk_aux_deckey"] = key.hex()
                config.entry["nwk_aux_decsrc"] = format(source_addr, "016x")
                config.entry["nwk_aux_decpayload"] = dec_payload.hex()

                # NWK Payload field (variable)
                if config.entry["nwk_frametype"] == "NWK Command":
                    dec_pkt = ZigbeeNWKCommandPayload(dec_payload)
                    config.entry["nwk_aux_decshow"] = (
                        dec_pkt.show(dump=True)
                    )
                    nwk_command(dec_pkt, msg_queue)
                    return
                elif config.entry["nwk_frametype"] == "NWK Data":
                    dec_pkt = ZigbeeAppDataPayload(dec_payload)
                    config.entry["nwk_aux_decshow"] = (
                        dec_pkt.show(dump=True)
                    )
                    aps_fields(dec_pkt, msg_queue)
                    return
                else:
                    config.entry["error_msg"] = (
                        "Unexpected format of the decrypted NWK payload"
                    )
                    return

    msg_queue.put(
        (config.DEBUG_MSG,
         "Unable to decrypt with a {} the NWK payload of packet #{} in {}"
         "".format(config.entry["nwk_aux_keytype"],
                   config.entry["pkt_num"],
                   config.entry["pcap_filename"])))
    config.entry["warning_msg"] = "PW301: Unable to decrypt the NWK payload"
    return


def nwk_fields(pkt, msg_queue):
    """Parse Zigbee NWK fields."""
    if config.entry["mac_frametype"] == "MAC Beacon":
        nwk_beacon(pkt)
        return
    elif config.entry["mac_frametype"] != "MAC Data":
        msg_queue.put(
            (config.DEBUG_MSG,
             "Packet #{} in {} contains unknown NWK fields"
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"])))
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

    # Destination Short Address field (2 bytes)
    config.entry["nwk_dstshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWK].destination)

    # Source Short Address field (2 bytes)
    config.entry["nwk_srcshortaddr"] = "0x{:04x}".format(
        pkt[ZigbeeNWK].source)

    # Radius field (1 byte)
    config.entry["nwk_radius"] = pkt[ZigbeeNWK].radius

    # Sequence Number field (1 byte)
    config.entry["nwk_seqnum"] = pkt[ZigbeeNWK].seqnum

    # Destination Extended Address field (0/8 bytes)
    if (config.entry["nwk_extendeddst"]
            == "NWK Extended Destination Included"):
        config.entry["nwk_dstextendedaddr"] = format(
            pkt[ZigbeeNWK].ext_dst, "016x")
    elif (config.entry["nwk_extendeddst"]
            != "NWK Extended Destination Omitted"):
        config.entry["error_msg"] = "Unknown Extended Destination state"
        return

    # Source Extended Address field (0/8 bytes)
    if (config.entry["nwk_extendedsrc"]
            == "NWK Extended Source Included"):
        config.entry["nwk_srcextendedaddr"] = format(
            pkt[ZigbeeNWK].ext_src, "016x")
    elif (config.entry["nwk_extendedsrc"]
            != "NWK Extended Source Omitted"):
        config.entry["error_msg"] = "Unknown Extended Source state"
        return

    # Multicast Control field (0/1 byte)
    if config.entry["nwk_multicast"] == "NWK Multicast Enabled":
        msg_queue.put(
            (config.DEBUG_MSG,
             "Packet #{} in {} contains a Multicast Control field "
             "which could not be processed"
             "".format(config.entry["pkt_num"],
                       config.entry["pcap_filename"])))
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
            "0x{:04x}".format(addr) for addr in pkt[ZigbeeNWK].relays)
    elif config.entry["nwk_srcroute"] != "NWK Source Route Omitted":
        config.entry["error_msg"] = "Unknown Source Route state"
        return

    if config.entry["nwk_security"] == "NWK Security Enabled":
        # NWK Auxiliary Header field (6/14 bytes)
        if pkt.haslayer(ZigbeeSecurityHeader):
            nwk_auxiliary(pkt, msg_queue)
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
                nwk_command(pkt, msg_queue)
                return
            else:
                config.entry["error_msg"] = "There are no NWK Command fields"
                return
        elif config.entry["nwk_frametype"] == "NWK Inter-PAN":
            msg_queue.put(
                (config.DEBUG_MSG,
                 "Packet #{} in {} contains Inter-PAN fields"
                 "which were ignored"
                 "".format(config.entry["pkt_num"],
                           config.entry["pcap_filename"])))
            config.entry["error_msg"] = "Ignored the Inter-PAN fields"
            return
        elif config.entry["nwk_frametype"] == "NWK Data":
            if pkt.haslayer(ZigbeeAppDataPayload):
                aps_fields(pkt, msg_queue)
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
