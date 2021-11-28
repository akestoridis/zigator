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

from scapy.all import (
    Dot15d4Data,
    Dot15d4FCS,
    ZDPDeviceAnnce,
    ZigbeeAppDataPayload,
    ZigbeeDeviceProfile,
    ZigbeeNWK,
)

from .secure_nwk_layer import secure_nwk_layer


def deviceannce(
    mac_seqnum,
    mac_dstpanid,
    mac_srcshortaddr,
    nwk_seqnum,
    nwk_srcextendedaddr,
    aps_counter,
    zdp_seqnum,
    nwk_aux_framecounter,
    nwk_aux_keyseqnum,
    nwk_key,
):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_dstpanid < 0 or mac_dstpanid.bit_length() > 16:
        raise ValueError("Invalid destination PAN ID")
    elif mac_srcshortaddr < 0 or mac_srcshortaddr.bit_length() > 16:
        raise ValueError("Invalid short source MAC address")
    elif nwk_seqnum < 0 or nwk_seqnum > 255:
        raise ValueError("Invalid NWK sequence number")
    elif nwk_srcextendedaddr < 0 or nwk_srcextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended source NWK address")
    elif aps_counter < 0 or aps_counter > 255:
        raise ValueError("Invalid APS counter")
    elif zdp_seqnum < 0 or zdp_seqnum > 255:
        raise ValueError("Invalid ZDP sequence number")
    elif nwk_aux_framecounter < 0 or nwk_aux_framecounter.bit_length() > 32:
        raise ValueError("Invalid NWK auxiliary frame counter")
    elif nwk_aux_keyseqnum < 0 or nwk_aux_keyseqnum > 255:
        raise ValueError("Invalid NWK auxiliary key sequence number")
    elif len(nwk_key) != 16:
        raise ValueError("Invalid network key length")

    # Forge a Device_annce
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=1,
            fcf_security=0,
            fcf_pending=0,
            fcf_ackreq=0,
            fcf_panidcompress=True,
            fcf_destaddrmode=2,
            fcf_framever=0,
            fcf_srcaddrmode=2,
            seqnum=mac_seqnum,
        )
        / Dot15d4Data(
            dest_panid=mac_dstpanid,
            dest_addr=0xffff,
            src_addr=mac_srcshortaddr,
        )
        / ZigbeeNWK(
            frametype=0,
            proto_version=2,
            discover_route=0,
            flags=0b010000,
            destination=0xfffd,
            source=mac_srcshortaddr,
            radius=30,
            seqnum=nwk_seqnum,
            ext_src=nwk_srcextendedaddr,
        )
        / ZigbeeAppDataPayload(
            aps_frametype=0,
            delivery_mode=2,
            frame_control=0b0000,
            dst_endpoint=0,
            cluster=0x0013,
            profile=0x0000,
            src_endpoint=0,
            counter=aps_counter,
        )
        / ZigbeeDeviceProfile(
            trans_seqnum=zdp_seqnum,
        )
        / ZDPDeviceAnnce(
            nwk_addr=mac_srcshortaddr,
            ieee_addr=nwk_srcextendedaddr,
            alternate_pan_coordinator=0,
            device_type=1,
            power_source=1,
            receiver_on_when_idle=1,
            security_capability=0,
            allocate_address=1,
        )
    )

    # Secure its NWK layer
    forged_pkt = secure_nwk_layer(
        forged_pkt,
        nwk_key,
        True,
        nwk_aux_framecounter,
        nwk_srcextendedaddr,
        nwk_aux_keyseqnum,
    )

    return forged_pkt
