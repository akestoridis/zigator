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
    Dot15d4FCS,
    ZigbeeAppCommandPayload,
    ZigbeeAppDataPayload,
    ZigbeeNWK,
    ZigbeeSecurityHeader,
)

from .. import crypto


def secure_aps_layer(
    pkt,
    key,
    keytype,
    extnonce,
    framecounter,
    srcaddr,
    keyseqnum=None,
):
    # Sanity checks
    if not pkt.haslayer(Dot15d4FCS):
        raise ValueError("The packet does not have IEEE 802.15.4 MAC fields")
    elif not pkt.haslayer(ZigbeeNWK):
        raise ValueError("The packet does not have NWK fields")
    elif not pkt.haslayer(ZigbeeAppDataPayload):
        raise ValueError("The packet does not have APS fields")
    elif pkt[ZigbeeAppDataPayload].frame_control.security:
        raise ValueError("The packet has already enabled APS security")
    elif (
        pkt[ZigbeeAppDataPayload].aps_frametype == 1
        and not pkt.haslayer(ZigbeeAppCommandPayload)
    ):
        raise ValueError("The packet does not have APS Command fields")
    elif (
        pkt[ZigbeeAppDataPayload].aps_frametype == 1
        and pkt[ZigbeeAppCommandPayload].cmd_identifier == 14
        and pkt[ZigbeeAppCommandPayload].frame_control.security
    ):
        raise ValueError("The packet has already enabled APS Tunnel security")

    # Separate the updated APS header and the decrypted APS payload
    if (
        pkt[ZigbeeAppDataPayload].aps_frametype == 1
        and pkt[ZigbeeAppCommandPayload].cmd_identifier == 14
    ):
        pkt[ZigbeeAppCommandPayload].frame_control.security = True
        tunneled_framecontrol = (
                pkt[ZigbeeAppCommandPayload].aps_frametype
                + 4*pkt[ZigbeeAppCommandPayload].delivery_mode
        )
        if pkt[ZigbeeAppCommandPayload].frame_control.ack_format:
            tunneled_framecontrol += 16
        if pkt[ZigbeeAppCommandPayload].frame_control.security:
            tunneled_framecontrol += 32
        if pkt[ZigbeeAppCommandPayload].frame_control.ack_req:
            tunneled_framecontrol += 64
        if pkt[ZigbeeAppCommandPayload].frame_control.extended_hdr:
            tunneled_framecontrol += 128
        tunneled_counter = pkt[ZigbeeAppCommandPayload].counter
        header = bytes([tunneled_framecontrol, tunneled_counter])
        dec_payload = bytes(pkt[ZigbeeAppCommandPayload].payload)
    else:
        pkt[ZigbeeAppDataPayload].frame_control.security = True
        aps_header = pkt[ZigbeeAppDataPayload].copy()
        aps_header.remove_payload()
        header = bytes(aps_header)
        dec_payload = bytes(pkt[ZigbeeAppDataPayload].payload)

    # Construct the auxiliary header
    if keytype == 0:
        # Use a data key to protect the packet
        if keyseqnum is not None:
            raise ValueError("Unexpected key sequence number")
        if extnonce:
            aux_bytearray = bytearray([0b00100000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
            aux_bytearray += srcaddr.to_bytes(8, byteorder="little")
        else:
            aux_bytearray = bytearray([0b00000000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
    elif keytype == 1:
        # Use a network key to protect the packet
        if keyseqnum is None:
            raise ValueError("Expected a key sequence number")
        if extnonce:
            aux_bytearray = bytearray([0b00101000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
            aux_bytearray += srcaddr.to_bytes(8, byteorder="little")
            aux_bytearray.append(keyseqnum)
        else:
            aux_bytearray = bytearray([0b00001000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
            aux_bytearray.append(keyseqnum)
    elif keytype == 2:
        # Use a key-transport key to protect the packet
        key = crypto.zigbee_hmac(bytes.fromhex("00"), key)
        if keyseqnum is not None:
            raise ValueError("Unexpected key sequence number")
        if extnonce:
            aux_bytearray = bytearray([0b00110000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
            aux_bytearray += srcaddr.to_bytes(8, byteorder="little")
        else:
            aux_bytearray = bytearray([0b00010000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
    elif keytype == 3:
        # Use a key-load key to protect the packet
        key = crypto.zigbee_hmac(bytes.fromhex("02"), key)
        if keyseqnum is not None:
            raise ValueError("Unexpected key sequence number")
        if extnonce:
            aux_bytearray = bytearray([0b00111000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
            aux_bytearray += srcaddr.to_bytes(8, byteorder="little")
        else:
            aux_bytearray = bytearray([0b00011000])
            aux_bytearray += framecounter.to_bytes(4, byteorder="little")
    else:
        raise ValueError("Unknown key type: {}".format(keytype))

    # Encrypt the APS payload and authenticate the APS header and APS payload
    enc_payload, mic = crypto.zigbee_enc_mic(
        key,
        srcaddr,
        framecounter,
        aux_bytearray[0],
        header,
        keyseqnum,
        dec_payload,
    )

    # Update the APS payload of the provided packet
    aux_bytearray += enc_payload + mic
    if (
        pkt[ZigbeeAppDataPayload].aps_frametype == 1
        and pkt[ZigbeeAppCommandPayload].cmd_identifier == 14
    ):
        pkt[ZigbeeAppCommandPayload].payload = ZigbeeSecurityHeader(
            bytes(aux_bytearray),
        )
    else:
        pkt[ZigbeeAppDataPayload].payload = ZigbeeSecurityHeader(
            bytes(aux_bytearray),
        )

    # Update the Frame Check Sequence (FCS) field of the provided packet
    pkt[Dot15d4FCS].fcs = int.from_bytes(
        pkt.compute_fcs(bytes(pkt)[:-2]),
        byteorder="little",
    )

    return pkt
