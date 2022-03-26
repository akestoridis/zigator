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
    LoWPAN_IPHC,
    LoWPAN_NHC,
    LoWPAN_NHC_UDP,
    MLE,
    MLECmd,
    Raw,
)

from .secure_mle_layer import secure_mle_layer


def childupdatereq(
    mac_seqnum,
    mac_dstpanid,
    mac_dstextendedaddr,
    mac_srcextendedaddr,
    thr_nhcudp_checksum,
    mle_cmd_payload,
    mle_aux_seclevel,
    mle_aux_keyidmode,
    mle_aux_framecounter,
    mle_aux_keysource,
    mle_aux_keyindex,
    mle_key,
    mle_noncesrcaddr,
):
    # Sanity checks
    if mac_seqnum < 0 or mac_seqnum > 255:
        raise ValueError("Invalid MAC sequence number")
    elif mac_dstpanid < 0 or mac_dstpanid.bit_length() > 16:
        raise ValueError("Invalid destination PAN ID")
    elif mac_dstextendedaddr < 0 or mac_dstextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended destination MAC address")
    elif mac_srcextendedaddr < 0 or mac_srcextendedaddr.bit_length() > 64:
        raise ValueError("Invalid extended source MAC address")
    elif thr_nhcudp_checksum < 0 or thr_nhcudp_checksum.bit_length() > 16:
        raise ValueError("Invalid NHC UDP checksum")
    elif mle_aux_seclevel not in {0, 1, 2, 3, 4, 5, 6, 7}:
        raise ValueError("Invalid MLE auxiliary security level field value")
    elif mle_aux_keyidmode not in {0, 1, 2, 3}:
        raise ValueError("Invalid MLE auxiliary key identifier mode")
    elif mle_aux_framecounter < 0 or mle_aux_framecounter.bit_length() > 32:
        raise ValueError("Invalid MLE auxiliary frame counter")
    elif (
        mle_aux_keysource is not None
        and (
            mle_aux_keysource < 0
            or mle_aux_keysource.bit_length() > 64
        )
    ):
        raise ValueError("Invalid MLE auxiliary key source")
    elif (
        mle_aux_keyindex is not None
        and (
            mle_aux_keyindex < 0
            or mle_aux_keyindex > 255
        )
    ):
        raise ValueError("Invalid MLE auxiliary key index")
    elif len(mle_key) != 16:
        raise ValueError("Invalid MLE key length")
    elif mle_noncesrcaddr < 0 or mle_noncesrcaddr.bit_length() > 64:
        raise ValueError("Invalid source address for the MLE nonce")

    # Forge a Child Update Request
    forged_pkt = (
        Dot15d4FCS(
            fcf_frametype=0b001,
            fcf_security=0b0,
            fcf_pending=0b0,
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
        / LoWPAN_IPHC(
            reserved=0b011,
            tf=0b11,
            nh=0b1,
            hlim=0b11,
            cid=0b0,
            sac=0b0,
            sam=0b11,
            m=0b0,
            dac=0b0,
            dam=0b11,
        )
        / LoWPAN_NHC(
            exts=LoWPAN_NHC_UDP(
                res=0b11110,
                C=0b0,
                P=0b00,
                udpSourcePort=19788,
                udpDestPort=19788,
                udpChecksum=thr_nhcudp_checksum,
            ),
        )
        / MLE(
            sec_suite=255,
        )
        / MLECmd(
            cmd_type=13,
        )
        / Raw(
            mle_cmd_payload,
        )
    )

    # Secure its MLE layer
    forged_pkt = secure_mle_layer(
        forged_pkt,
        mle_key,
        mle_noncesrcaddr,
        mle_aux_seclevel,
        mle_aux_keyidmode,
        mle_aux_framecounter,
        mle_aux_keysource,
        mle_aux_keyindex,
    )

    # Sanity check
    if len(bytes(forged_pkt)) > 127:
        raise ValueError(
            "Invalid packet length: {}".format(len(bytes(forged_pkt))),
        )

    return forged_pkt
