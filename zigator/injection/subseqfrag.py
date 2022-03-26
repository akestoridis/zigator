# Copyright (C) 2022 Dimitrios-Georgios Akestoridis
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
    LoWPANFragmentationSubsequent,
    Raw,
)

from .secure_mac_layer import secure_mac_layer


def subseqfrag(
    mac_framepending,
    mac_seqnum,
    mac_dstpanid,
    mac_dstextendedaddr,
    mac_srcextendedaddr,
    thr_subseqfrag_datagramsize,
    thr_subseqfrag_datagramtag,
    thr_subseqfrag_datagramoffset,
    thr_subseqfrag_payload,
    mac_security,
    mac_aux_seclevel,
    mac_aux_keyidmode,
    mac_aux_framecounter,
    mac_aux_keysource,
    mac_aux_keyindex,
    mac_key,
    mac_noncesrcaddr,
):
    # Sanity checks
    if mac_framepending not in {0, 1}:
        raise ValueError("Invalid MAC frame pending field value")
    elif mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_dstpanid < 0 or mac_dstpanid.bit_length() > 16:
        raise ValueError("Invalid destination PAN ID")
    elif mac_dstextendedaddr < 0 or mac_dstextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended destination MAC address")
    elif mac_srcextendedaddr < 0 or mac_srcextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended source MAC address")
    elif (
        thr_subseqfrag_datagramsize < 0
        or thr_subseqfrag_datagramsize.bit_length() > 11
    ):
        raise ValueError("Invalid datagram size")
    elif (
        thr_subseqfrag_datagramtag < 0
        or thr_subseqfrag_datagramtag.bit_length() > 16
    ):
        raise ValueError("Invalid datagram tag")
    elif (
        thr_subseqfrag_datagramoffset < 0
        or thr_subseqfrag_datagramoffset > 255
    ):
        raise ValueError("Invalid datagram offset")
    elif mac_security not in {0, 1}:
        raise ValueError("Invalid MAC security field value")
    elif mac_aux_seclevel not in {0, 1, 2, 3, 4, 5, 6, 7}:
        raise ValueError("Invalid MAC auxiliary security level field value")
    elif mac_aux_keyidmode not in {0, 1, 2, 3}:
        raise ValueError("Invalid MAC auxiliary key identifier mode")
    elif mac_aux_framecounter < 0 or mac_aux_framecounter.bit_length() > 32:
        raise ValueError("Invalid MAC auxiliary frame counter")
    elif (
        mac_aux_keysource is not None
        and (
            mac_aux_keysource < 0
            or mac_aux_keysource.bit_length() > 64
        )
    ):
        raise ValueError("Invalid MAC auxiliary key source")
    elif (
        mac_aux_keyindex is not None
        and (
            mac_aux_keyindex < 0
            or mac_aux_keyindex > 255
        )
    ):
        raise ValueError("Invalid MAC auxiliary key index")
    elif len(mac_key) != 16:
        raise ValueError("Invalid MAC key length")
    elif mac_noncesrcaddr < 0 or mac_noncesrcaddr.bit_length() > 64:
        raise ValueError("Invalid source address for the MAC nonce")

    # Forge a subsequent fragment
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=0b001,
            fcf_security=0b0,
            fcf_pending=mac_framepending,
            fcf_ackreq=0b1,
            fcf_panidcompress=True,
            fcf_destaddrmode=0b11,
            fcf_framever=0b01,
            fcf_srcaddrmode=0b11,
            seqnum=mac_seqnum,
        )
        / Dot15d4Data(
            dest_panid=mac_dstpanid,
            dest_addr=mac_dstextendedaddr,
            src_addr=mac_srcextendedaddr,
        )
        / LoWPANFragmentationSubsequent(
            reserved=0b11100,
            datagramSize=thr_subseqfrag_datagramsize,
            datagramTag=thr_subseqfrag_datagramtag,
            datagramOffset=thr_subseqfrag_datagramoffset,
        )
        / Raw(
            thr_subseqfrag_payload,
        )
    )

    # Check whether its MAC layer should be secured or not
    if mac_security == 1:
        forged_pkt = secure_mac_layer(
            forged_pkt,
            mac_key,
            mac_noncesrcaddr,
            mac_aux_seclevel,
            mac_aux_keyidmode,
            mac_aux_framecounter,
            mac_aux_keysource,
            mac_aux_keyindex,
        )

    # Sanity check
    if len(bytes(forged_pkt)) > 127:
        raise ValueError(
            "Invalid packet length: {}".format(len(bytes(forged_pkt))),
        )

    return forged_pkt
