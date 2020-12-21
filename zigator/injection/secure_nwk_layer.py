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

from scapy.all import Dot15d4FCS
from scapy.all import ZigbeeNWK
from scapy.all import ZigbeeSecurityHeader

from .. import crypto


def secure_nwk_layer(pkt, key, extnonce, framecounter, srcaddr, keyseqnum):
    # Sanity checks
    if not pkt.haslayer(Dot15d4FCS):
        raise ValueError("The packet does not have IEEE 802.15.4 MAC fields")
    elif not pkt.haslayer(ZigbeeNWK):
        raise ValueError("The packet does not have NWK fields")
    elif pkt[ZigbeeNWK].flags.security:
        raise ValueError("The packet has already enabled NWK security")

    # Separate the updated NWK header and the decrypted NWK payload
    pkt[ZigbeeNWK].flags.security = True
    nwk_header = pkt[ZigbeeNWK].copy()
    nwk_header.remove_payload()
    header = bytes(nwk_header)
    dec_payload = bytes(pkt[ZigbeeNWK].payload)

    # Construct the auxiliary header
    if extnonce:
        aux_bytearray = bytearray([0b00101000])
        aux_bytearray += framecounter.to_bytes(4, byteorder="little")
        aux_bytearray += srcaddr.to_bytes(8, byteorder="little")
        aux_bytearray.append(keyseqnum)
    else:
        aux_bytearray = bytearray([0b00001000])
        aux_bytearray += framecounter.to_bytes(4, byteorder="little")
        aux_bytearray.append(keyseqnum)

    # Encrypt the NWK payload and authenticate the NWK header and NWK payload
    enc_payload, mic = crypto.zigbee_enc_mic(
        key, srcaddr, framecounter, aux_bytearray[0],
        header, keyseqnum, dec_payload)

    # Update the NWK payload of the provided packet
    aux_bytearray += enc_payload + mic
    pkt[ZigbeeNWK].payload = ZigbeeSecurityHeader(bytes(aux_bytearray))

    # Update the Frame Check Sequence (FCS) field of the provided packet
    pkt[Dot15d4FCS].fcs = int.from_bytes(
        pkt.compute_fcs(bytes(pkt)[:-2]), byteorder="little")

    return pkt
