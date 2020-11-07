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

from scapy.all import Dot15d4Beacon
from scapy.all import Dot15d4Cmd
from scapy.all import Dot15d4CmdAssocReq
from scapy.all import Dot15d4CmdAssocResp
from scapy.all import Dot15d4CmdDisassociation
from scapy.all import Dot15d4CmdGTSReq
from scapy.all import Dot15d4FCS


def get_mac_frametype(pkt):
    mac_frametypes = {
        0: "MAC Beacon",
        1: "MAC Data",
        2: "MAC Acknowledgment",
        3: "MAC Command"
    }
    frametype_id = pkt[Dot15d4FCS].fcf_frametype
    return mac_frametypes.get(frametype_id, "Unknown MAC frame type")


def get_mac_security(pkt):
    mac_security_states = {
        0: "MAC Security Disabled",
        1: "MAC Security Enabled"
    }
    sec_state = pkt[Dot15d4FCS].fcf_security
    return mac_security_states.get(sec_state, "Unknown MAC security state")


def get_mac_framepending(pkt):
    mac_framepending_states = {
        0: "No additional packets are pending for the receiver",
        1: "Additional packets are pending for the receiver"
    }
    fp_state = pkt[Dot15d4FCS].fcf_pending
    return mac_framepending_states.get(fp_state, "Unknown MAC FP state")


def get_mac_ackreq(pkt):
    mac_ackreq_states = {
        0: "The sender does not request a MAC Acknowledgment",
        1: "The sender requests a MAC Acknowledgment"
    }
    ar_state = pkt[Dot15d4FCS].fcf_ackreq
    return mac_ackreq_states.get(ar_state, "Unknown MAC AR state")


def get_mac_panidcomp(pkt):
    mac_panidcomp_states = {
        0: "Do not compress the source PAN ID",
        1: "The source PAN ID is the same as the destination PAN ID"
    }
    pc_state = pkt[Dot15d4FCS].fcf_panidcompress
    return mac_panidcomp_states.get(pc_state, "Unknown MAC PC state")


def get_mac_dstaddrmode(pkt):
    mac_dstaddr_modes = {
        0: "No destination MAC address",
        2: "Short destination MAC address",
        3: "Extended destination MAC address"
    }
    dstaddr_mode = pkt[Dot15d4FCS].fcf_destaddrmode
    return mac_dstaddr_modes.get(dstaddr_mode, "Unknown MAC DA mode")


def get_mac_frameversion(pkt):
    mac_frame_versions = {
        0: "IEEE 802.15.4-2003 Frame Version",
        1: "IEEE 802.15.4-2006 Frame Version",
        2: "IEEE 802.15.4-2015 Frame Version"
    }
    fv_id = pkt[Dot15d4FCS].fcf_framever
    return mac_frame_versions.get(fv_id, "Unknown MAC frame version")


def get_mac_srcaddrmode(pkt):
    mac_srcaddr_modes = {
        0: "No source MAC address",
        2: "Short source MAC address",
        3: "Extended source MAC address"
    }
    srcaddr_mode = pkt[Dot15d4FCS].fcf_srcaddrmode
    return mac_srcaddr_modes.get(srcaddr_mode, "Unknown MAC SA mode")


def get_mac_command(pkt):
    mac_commands = {
        1: "MAC Association Request",
        2: "MAC Association Response",
        3: "MAC Disassociation Notification",
        4: "MAC Data Request",
        5: "MAC PAN ID Conflict Notification",
        6: "MAC Orphan Notification",
        7: "MAC Beacon Request",
        8: "MAC Coordinator Realignment",
        9: "MAC GTS Request"
    }
    command_id = pkt[Dot15d4Cmd].cmd_id
    return mac_commands.get(command_id, "Unknown MAC Command")


def get_mac_assocreq_apc(pkt):
    apc_states = {
        0: "The sender is not capable of becoming a PAN coordinator",
        1: "The sender is capable of becoming a PAN coordinator"
    }
    apc_state = pkt[Dot15d4CmdAssocReq].alternate_pan_coordinator
    return apc_states.get(apc_state, "Unknown APC state")


def get_mac_assocreq_devtype(pkt):
    device_types = {
        0: "Reduced-Function Device",
        1: "Full-Function Device"
    }
    devtype_id = pkt[Dot15d4CmdAssocReq].device_type
    return device_types.get(devtype_id, "Unknown device type")


def get_mac_assocreq_powsrc(pkt):
    power_sources = {
        0: "The sender is not a mains-powered device",
        1: "The sender is a mains-powered device"
    }
    pwrsrc_id = pkt[Dot15d4CmdAssocReq].power_source
    return power_sources.get(pwrsrc_id, "Unknown power source")


def get_mac_assocreq_rxidle(pkt):
    rxidle_states = {
        0: "Disables the receiver to conserve power when idle",
        1: "Does not disable the receiver to conserve power"
    }
    rxidle_state = pkt[Dot15d4CmdAssocReq].receiver_on_when_idle
    return rxidle_states.get(rxidle_state, "Unknown RX state when idle")


def get_mac_assocreq_seccap(pkt):
    seccap_states = {
        0: "Cannot transmit and receive secure MAC frames",
        1: "Can transmit and receive secure MAC frames"
    }
    seccap_state = pkt[Dot15d4CmdAssocReq].security_capability
    return seccap_states.get(seccap_state, "Unknown MAC security capacity")


def get_mac_assocreq_allocaddr(pkt):
    allocaddr_states = {
        0: "Does not request a short address",
        1: "Requests a short address"
    }
    allocaddr_state = pkt[Dot15d4CmdAssocReq].allocate_address
    return allocaddr_states.get(allocaddr_state, "Unknown address allocation")


def get_mac_assocrsp_status(pkt):
    assoc_statuses = {
        0: "Association successful",
        1: "PAN at capacity",
        2: "PAN access denied"
    }
    assoc_status = pkt[Dot15d4CmdAssocResp].association_status
    return assoc_statuses.get(assoc_status, "Unknown association status")


def get_mac_disassoc_reason(pkt):
    disassoc_reasons = {
        1: "The coordinator wishes the device to leave the PAN",
        2: "The device wishes to leave the PAN"
    }
    reason_id = pkt[Dot15d4CmdDisassociation].disassociation_reason
    return disassoc_reasons.get(reason_id, "Unknown disassociation reason")


def get_mac_gtsreq_dir(pkt):
    gts_direction = {
        0: "Transmit-Only GTS",
        1: "Receive-Only GTS"
    }
    dir_id = pkt[Dot15d4CmdGTSReq].gts_dir
    return gts_direction.get(dir_id, "Unknown GTS direction")


def get_mac_gtsreq_chartype(pkt):
    charact_types = {
        0: "GTS Deallocation",
        1: "GTS Allocation"
    }
    chartype_id = pkt[Dot15d4CmdGTSReq].charact_type
    return charact_types.get(chartype_id, "Unknown GTS characteristics type")


def get_mac_beacon_pancoord(pkt):
    panc_states = {
        0: "The sender is not the PAN coordinator",
        1: "The sender is the PAN coordinator"
    }
    panc_state = pkt[Dot15d4Beacon].sf_pancoord
    return panc_states.get(panc_state, "Unknown PAN coordinator state")


def get_mac_beacon_assocpermit(pkt):
    assocp_states = {
        0: "The sender is currently not accepting association requests",
        1: "The sender is currently accepting association requests"
    }
    assocp_state = pkt[Dot15d4Beacon].sf_assocpermit
    return assocp_states.get(assocp_state, "Unknown Association Permit state")
