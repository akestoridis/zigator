# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis
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
    ZigbeeNWK,
    ZigbeeNWKCommandPayload,
)

from .secure_nwk_layer import secure_nwk_layer


def rejoinreq(
    mac_seqnum,
    mac_dstpanid,
    mac_dstshortaddr,
    mac_srcshortaddr,
    nwk_seqnum,
    nwk_srcextendedaddr,
    nwk_rejoinreq_devtype,
    nwk_rejoinreq_powsrc,
    nwk_rejoinreq_rxidle,
    nwk_security,
    nwk_aux_framecounter,
    nwk_aux_keyseqnum,
    nwk_key,
):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_dstpanid < 0 or mac_dstpanid.bit_length() > 16:
        raise ValueError("Invalid destination PAN ID")
    elif mac_dstshortaddr < 0 or mac_dstshortaddr.bit_length() > 16:
        raise ValueError("Invalid short destination MAC address")
    elif mac_srcshortaddr < 0 or mac_srcshortaddr.bit_length() > 16:
        raise ValueError("Invalid short source MAC address")
    elif nwk_seqnum < 0 or nwk_seqnum > 255:
        raise ValueError("Invalid NWK sequence number")
    elif nwk_srcextendedaddr < 0 or nwk_srcextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended source NWK address")
    elif nwk_rejoinreq_devtype not in {0, 1}:
        raise ValueError("Invalid Device Type rejoin request field value")
    elif nwk_rejoinreq_powsrc not in {0, 1}:
        raise ValueError("Invalid Power Source rejoin request field value")
    elif nwk_rejoinreq_rxidle not in {0, 1}:
        raise ValueError(
            "Invalid Receiver On When Idle rejoin request field value",
        )
    elif nwk_security not in {0, 1}:
        raise ValueError("Invalid NWK security field value")
    elif nwk_aux_framecounter < 0 or nwk_aux_framecounter.bit_length() > 32:
        raise ValueError("Invalid NWK auxiliary frame counter")
    elif nwk_aux_keyseqnum < 0 or nwk_aux_keyseqnum > 255:
        raise ValueError("Invalid NWK auxiliary key sequence number")
    elif len(nwk_key) != 16:
        raise ValueError("Invalid network key length")

    # Forge a Rejoin Request
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
            seqnum=mac_seqnum,
        )
        / Dot15d4Data(
            dest_panid=mac_dstpanid,
            dest_addr=mac_dstshortaddr,
            src_addr=mac_srcshortaddr,
        )
        / ZigbeeNWK(
            frametype=1,
            proto_version=2,
            discover_route=0,
            flags=0b010000,
            destination=mac_dstshortaddr,
            source=mac_srcshortaddr,
            radius=1,
            seqnum=nwk_seqnum,
            ext_src=nwk_srcextendedaddr,
        )
        / ZigbeeNWKCommandPayload(
            cmd_identifier=6,
            alternate_pan_coordinator=0,
            device_type=nwk_rejoinreq_devtype,
            power_source=nwk_rejoinreq_powsrc,
            receiver_on_when_idle=nwk_rejoinreq_rxidle,
            security_capability=0,
            allocate_address=1,
        )
    )

    # Check whether its NWK layer should be secured or not
    if nwk_security == 1:
        forged_pkt = secure_nwk_layer(
            forged_pkt,
            nwk_key,
            True,
            nwk_aux_framecounter,
            nwk_srcextendedaddr,
            nwk_aux_keyseqnum,
        )

    return forged_pkt
