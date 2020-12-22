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

from scapy.all import Dot15d4Data
from scapy.all import Dot15d4FCS
from scapy.all import ZigbeeAppCommandPayload
from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigbeeNWK

from .secure_aps_layer import secure_aps_layer
from .secure_nwk_layer import secure_nwk_layer


def updatedevice(mac_seqnum, mac_dstpanid, mac_dstshortaddr, mac_srcshortaddr,
                 nwk_dstshortaddr, nwk_srcshortaddr, nwk_radius, nwk_seqnum,
                 aps_counter, aps_updatedevice_extendedaddr,
                 aps_updatedevice_shortaddr, aps_updatedevice_status,
                 nwk_aux_framecounter, nwk_aux_srcaddr, nwk_aux_keyseqnum,
                 nwk_key, aps_security, aps_aux_extnonce,
                 aps_aux_framecounter, aps_aux_srcaddr, aps_key):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_dstpanid < 0 or mac_dstpanid.bit_length() > 16:
        raise ValueError("Invalid destination PAN ID")
    elif mac_dstshortaddr < 0 or mac_dstshortaddr.bit_length() > 16:
        raise ValueError("Invalid short destination MAC address")
    elif mac_srcshortaddr < 0 or mac_srcshortaddr.bit_length() > 16:
        raise ValueError("Invalid short source MAC address")
    elif nwk_dstshortaddr < 0 or nwk_dstshortaddr.bit_length() > 16:
        raise ValueError("Invalid short destination NWK address")
    elif nwk_srcshortaddr < 0 or nwk_srcshortaddr.bit_length() > 16:
        raise ValueError("Invalid short source NWK address")
    elif nwk_radius < 0 or nwk_radius > 255:
        raise ValueError("Invalid NWK radius")
    elif nwk_seqnum < 0 or nwk_seqnum > 255:
        raise ValueError("Invalid NWK sequence number")
    elif aps_counter < 0 or aps_counter > 255:
        raise ValueError("Invalid APS counter")
    elif (aps_updatedevice_extendedaddr < 0
            or aps_updatedevice_extendedaddr.bit_length() > 64):
        raise ValueError("Invalid extended Update-Device address")
    elif (aps_updatedevice_shortaddr < 0
            or aps_updatedevice_shortaddr.bit_length() > 16):
        raise ValueError("Invalid short Update-Device address")
    elif aps_updatedevice_status not in {0, 1, 2, 3}:
        raise ValueError("Invalid Update-Device status field value")
    elif nwk_aux_framecounter < 0 or nwk_aux_framecounter.bit_length() > 32:
        raise ValueError("Invalid NWK auxiliary frame counter")
    elif nwk_aux_srcaddr < 0 or nwk_aux_srcaddr.bit_length() > 64:
        raise ValueError("Invalid NWK auxiliary extended source address")
    elif nwk_aux_keyseqnum < 0 or nwk_aux_keyseqnum > 255:
        raise ValueError("Invalid NWK auxiliary key sequence number")
    elif len(nwk_key) != 16:
        raise ValueError("Invalid network key length")
    elif aps_security not in {0, 1}:
        raise ValueError("Invalid APS security field value")
    elif aps_aux_extnonce not in {False, True}:
        raise ValueError("Invalid APS auxiliary extended nonce field value")
    elif aps_aux_framecounter < 0 or aps_aux_framecounter.bit_length() > 32:
        raise ValueError("Invalid APS auxiliary frame counter")
    elif aps_aux_srcaddr < 0 or aps_aux_srcaddr.bit_length() > 64:
        raise ValueError("Invalid APS auxiliary extended source address")
    elif len(aps_key) != 16:
        raise ValueError("Invalid link key length")

    # Forge an Update-Device command
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=1,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=1,
            fcf_panidcompress=True,
            fcf_destaddrmode=2,
            fcf_framever=0,
            fcf_srcaddrmode=2,
            seqnum=mac_seqnum)
        / Dot15d4Data(
            dest_panid=mac_dstpanid,
            dest_addr=mac_dstshortaddr,
            src_addr=mac_srcshortaddr)
        / ZigbeeNWK(
            frametype=0,
            proto_version=2,
            discover_route=0,
            flags=0b000000,
            destination=nwk_dstshortaddr,
            source=nwk_srcshortaddr,
            radius=nwk_radius,
            seqnum=nwk_seqnum)
        / ZigbeeAppDataPayload(
            aps_frametype=1,
            delivery_mode=0,
            frame_control=0b0000,
            counter=aps_counter)
        / ZigbeeAppCommandPayload(
            cmd_identifier=6,
            address=aps_updatedevice_extendedaddr,
            short_address=aps_updatedevice_shortaddr,
            status=aps_updatedevice_status)
    )

    # Check whether its APS layer should be secured or not
    if aps_security == 1:
        forged_pkt = secure_aps_layer(
            forged_pkt,
            aps_key,
            0,
            aps_aux_extnonce,
            aps_aux_framecounter,
            aps_aux_srcaddr)

    # Secure its NWK layer
    forged_pkt = secure_nwk_layer(
        forged_pkt,
        nwk_key,
        True,
        nwk_aux_framecounter,
        nwk_aux_srcaddr,
        nwk_aux_keyseqnum)

    return forged_pkt
