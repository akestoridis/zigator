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
    Dot15d4AuxSecurityHeader,
    Dot15d4Beacon,
    Dot15d4Cmd,
    Dot15d4Data,
    Dot15d4FCS,
)

from .. import crypto


def secure_mac_layer(
    pkt,
    key,
    srcaddr,
    seclevel,
    keyidmode,
    framecounter,
    keysource,
    keyindex,
):
    # Sanity checks
    if not pkt.haslayer(Dot15d4FCS):
        raise ValueError("The packet does not have IEEE 802.15.4 MAC fields")
    elif pkt[Dot15d4FCS].fcf_security == 1:
        raise ValueError("The packet has already enabled MAC security")

    # Determine the MAC frame type
    if pkt.haslayer(Dot15d4Data):
        frametype_layer = Dot15d4Data
    elif pkt.haslayer(Dot15d4Beacon):
        frametype_layer = Dot15d4Beacon
    elif pkt.haslayer(Dot15d4Cmd):
        frametype_layer = Dot15d4Cmd
    else:
        raise ValueError("Unexpected MAC frame type")

    # Separate the updated MAC header and the decrypted MAC payload
    pkt[Dot15d4FCS].fcf_security = 1
    mac_header = pkt[Dot15d4FCS].copy()
    mac_header.remove_payload()
    header = bytes(mac_header)[:-2]
    pkt[frametype_layer].aux_sec_header = Dot15d4AuxSecurityHeader(
        sec_sc_seclevel=seclevel,
        sec_sc_keyidmode=keyidmode,
        sec_framecounter=framecounter,
        sec_keyid_keysource=keysource,
        sec_keyid_keyindex=keyindex,
    )
    unenc_data = pkt[frametype_layer].copy()
    unenc_data.remove_payload()
    header += bytes(unenc_data)
    dec_payload = bytes(pkt[frametype_layer].payload)

    # Secure the MAC payload and generate a message integrity code based on
    # the provided security level
    sec_payload, mic = crypto.ieee802154_enc_mic(
        key,
        srcaddr,
        framecounter,
        seclevel,
        header,
        dec_payload,
    )

    # Update the corresponding MAC header
    pkt[frametype_layer].sec_payload = sec_payload
    pkt[frametype_layer].mic = mic
    pkt[frametype_layer].remove_payload()

    # Update the Frame Check Sequence (FCS) field of the provided packet
    pkt[Dot15d4FCS].fcs = int.from_bytes(
        pkt.compute_fcs(bytes(pkt)[:-2]),
        byteorder="little",
    )

    return pkt
