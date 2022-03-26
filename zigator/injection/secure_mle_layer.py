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

from ipaddress import IPv6Address

from scapy.all import (
    Dot15d4AuxSecurityHeader,
    Dot15d4Data,
    Dot15d4FCS,
    IPv6,
    LoWPAN_IPHC,
    LoWPAN_NHC,
    LoWPAN_NHC_UDP,
    MLE,
    MLECmd,
    UDP,
    conf,
)

from .. import crypto


def secure_mle_layer(
    pkt,
    key,
    srcaddr,
    seclevel,
    keyidmode,
    framecounter,
    keysource,
    keyindex,
):
    # Decompress compressed headers
    prev_dot15d4_protocol = conf.dot15d4_protocol
    conf.dot15d4_protocol = "sixlowpan"
    pkt = Dot15d4FCS(bytes(pkt))
    conf.dot15d4_protocol = prev_dot15d4_protocol

    # Sanity checks
    if not pkt.haslayer(Dot15d4FCS):
        raise ValueError("The packet does not have IEEE 802.15.4 MAC fields")
    elif not pkt.haslayer(Dot15d4Data):
        raise ValueError("The packet does not have MAC Data fields")
    elif not pkt.haslayer(LoWPAN_IPHC):
        raise ValueError("The packet does not have IPHC fields")
    elif not pkt.haslayer(LoWPAN_NHC):
        raise ValueError("The packet does not have NHC fields")
    elif not pkt.haslayer(LoWPAN_NHC_UDP):
        raise ValueError("The packet does not have NHC UDP fields")
    elif not pkt.haslayer(IPv6):
        raise ValueError("The packet does not have decompressed IPv6 fields")
    elif not pkt.haslayer(UDP):
        raise ValueError("The packet does not have decompressed UDP fields")
    elif not pkt.haslayer(MLE):
        raise ValueError("The packet does not have MLE fields")
    elif not pkt.haslayer(MLECmd):
        raise ValueError("The packet does not have MLE Command fields")
    elif pkt[MLE].sec_suite != 255:
        raise ValueError("The packet has already enabled MLE security")

    # Separate the updated header and the decrypted MLE payload
    pkt[MLE].sec_suite = 0
    pkt[MLE].aux_sec_header = Dot15d4AuxSecurityHeader(
        sec_sc_seclevel=seclevel,
        sec_sc_keyidmode=keyidmode,
        sec_framecounter=framecounter,
        sec_keyid_keysource=keysource,
        sec_keyid_keyindex=keyindex,
    )
    header = (
        IPv6Address(pkt[IPv6].src).packed
        + IPv6Address(pkt[IPv6].dst).packed
        + bytes(pkt[MLE].aux_sec_header)
    )
    dec_payload = bytes(pkt[MLE].payload)

    # Secure the MLE payload and generate a message integrity code based on
    # the provided security level
    sec_payload, mic = crypto.ieee802154_enc_mic(
        key,
        srcaddr,
        framecounter,
        seclevel,
        header,
        dec_payload,
    )

    # Update the MLE header
    pkt[MLE].sec_payload = sec_payload
    pkt[MLE].mic = mic
    pkt[MLE].remove_payload()

    # Update the Frame Check Sequence (FCS) field of the provided packet
    pkt[Dot15d4FCS].fcs = int.from_bytes(
        pkt.compute_fcs(bytes(pkt)[:-2]),
        byteorder="little",
    )

    return pkt
