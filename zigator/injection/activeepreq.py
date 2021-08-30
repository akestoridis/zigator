# Copyright (C) 2021 Dimitrios-Georgios Akestoridis
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
from scapy.all import ZDPActiveEPReq
from scapy.all import ZigbeeAppDataPayload
from scapy.all import ZigbeeDeviceProfile
from scapy.all import ZigbeeNWK

from .secure_nwk_layer import secure_nwk_layer


def activeepreq(mac_seqnum, mac_dstpanid, mac_dstshortaddr, nwk_seqnum,
                aps_counter, zdp_seqnum, nwk_aux_framecounter,
                nwk_aux_srcaddr, nwk_aux_keyseqnum, nwk_key):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_dstpanid < 0 or mac_dstpanid.bit_length() > 16:
        raise ValueError("Invalid destination PAN ID")
    elif mac_dstshortaddr < 0 or mac_dstshortaddr.bit_length() > 16:
        raise ValueError("Invalid short destination MAC address")
    elif nwk_seqnum < 0 or nwk_seqnum > 255:
        raise ValueError("Invalid NWK sequence number")
    elif aps_counter < 0 or aps_counter > 255:
        raise ValueError("Invalid APS counter")
    elif zdp_seqnum < 0 or zdp_seqnum > 255:
        raise ValueError("Invalid ZDP sequence number")
    elif nwk_aux_framecounter < 0 or nwk_aux_framecounter.bit_length() > 32:
        raise ValueError("Invalid NWK auxiliary frame counter")
    elif nwk_aux_srcaddr < 0 or nwk_aux_srcaddr.bit_length() > 64:
        raise ValueError("Invalid NWK auxiliary source address")
    elif nwk_aux_keyseqnum < 0 or nwk_aux_keyseqnum > 255:
        raise ValueError("Invalid NWK auxiliary key sequence number")
    elif len(nwk_key) != 16:
        raise ValueError("Invalid network key length")

    # Forge an Active_EP_req
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
            src_addr=0x0000)
        / ZigbeeNWK(
            frametype=0,
            proto_version=2,
            discover_route=0,
            flags=0b000000,
            destination=mac_dstshortaddr,
            source=0x0000,
            radius=30,
            seqnum=nwk_seqnum)
        / ZigbeeAppDataPayload(
            aps_frametype=0,
            delivery_mode=0,
            frame_control=0b0100,
            dst_endpoint=0,
            cluster=0x0005,
            profile=0x0000,
            src_endpoint=0,
            counter=aps_counter)
        / ZigbeeDeviceProfile(
            trans_seqnum=zdp_seqnum)
        / ZDPActiveEPReq(
            nwk_addr=mac_dstshortaddr)
    )

    # Secure its NWK layer
    forged_pkt = secure_nwk_layer(
        forged_pkt,
        nwk_key,
        True,
        nwk_aux_framecounter,
        nwk_aux_srcaddr,
        nwk_aux_keyseqnum)

    return forged_pkt
