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

import logging

from scapy.all import (
    CookedLinux,
    Dot15d4,
    Dot15d4Data,
    Dot15d4FCS,
    IPv6,
    LoWPANFragmentationFirst,
    LoWPANFragmentationSubsequent,
    LoWPANMesh,
    LoWPAN_IPHC,
    LoWPAN_NHC,
    LoWPAN_NHC_IPv6Ext,
    LoWPAN_NHC_UDP,
    MLE,
    Raw,
    ThreadBeacon,
    UDP,
)

from .. import config
from ..enums import Message
from .mle_fields import mle_fields


THR_VF_MODES = {
    0: "0b0: 64-bit Very First Address",
    1: "0b1: 16-bit Very First Address",
}

THR_FD_MODES = {
    0: "0b0: 64-bit Final Destination Address",
    1: "0b1: 16-bit Final Destination Address",
}

THR_TF_MODES = {
    0: "0b00: In-line ECN, DSCP, and FL",
    1: "0b01: In-line ECN and FL; Compressed DSCP",
    2: "0b10: In-line ECN and DSCP; Compressed FL",
    3: "0b11: Compressed ECN, DSCP, and FL",
}

THR_NH_MODES = {
    0: "0b0: In-line Next Header",
    1: "0b1: Compressed Next Header",
}

THR_HLIM_MODES = {
    0: "0b00: In-line Hop Limit",
    1: "0b01: Compressed Hop Limit; Hop limit is 1",
    2: "0b10: Compressed Hop Limit; Hop limit is 64",
    3: "0b11: Compressed Hop Limit; Hop limit is 255",
}

THR_CID_STATES = {
    0: "0b0: Absent Context Identifier Extension",
    1: "0b1: Present Context Identifier Extension",
}

THR_SAC_STATES = {
    0: "0b0: Stateless Source Address Compression",
    1: "0b1: Stateful Source Address Compression",
}

THR_STATELESS_SOURCE_ADDRESS_MODES = {
    0: "0b00: 128 bits of the source address are present",
    1: "0b01: 64 bits of the source address are present",
    2: "0b10: 16 bits of the source address are present",
    3: "0b11: 0 bits of the source address are present",
}

THR_STATEFUL_SOURCE_ADDRESS_MODES = {
    0: "0b00: Unspecified source address",
    1: "0b01: 64 bits of the source address are present",
    2: "0b10: 16 bits of the source address are present",
    3: "0b11: 0 bits of the source address are present",
}

THR_MULTICAST_STATES = {
    0: "0b0: Not multicasting",
    1: "0b1: Multicasting",
}

THR_DAC_STATES = {
    0: "0b0: Stateless Destination Address Compression",
    1: "0b1: Stateful Destination Address Compression",
}

THR_STATELESS_UNICAST_DESTINATION_ADDRESS_MODES = {
    0: "0b00: 128 bits of the destination address are present",
    1: "0b01: 64 bits of the destination address are present",
    2: "0b10: 16 bits of the destination address are present",
    3: "0b11: 0 bits of the destination address are present",
}

THR_STATEFUL_UNICAST_DESTINATION_ADDRESS_MODES = {
    1: "0b01: 64 bits of the destination address are present",
    2: "0b10: 16 bits of the destination address are present",
    3: "0b11: 0 bits of the destination address are present",
}

THR_STATELESS_MULTICAST_DESTINATION_ADDRESS_MODES = {
    0: "0b00: 128 bits of the destination address are present",
    1: "0b01: 48 bits of the destination address are present",
    2: "0b10: 32 bits of the destination address are present",
    3: "0b11: 8 bits of the destination address are present",
}

THR_STATEFUL_MULTICAST_DESTINATION_ADDRESS_MODES = {
    0: "0b00: 48 bits of the destination address are present",
}

THR_NHCUDP_CHECKSUM_MODES = {
    0: "0b0: In-line Checksum",
    1: "0b1: Compressed Checksum",
}

THR_NHCUDP_PORTS_MODES = {
    0: "0b00: In-line source and destination ports",
    1: "0b01: In-line source port; Compressed destination port",
    2: "0b10: In-line destination port; Compressed source port",
    3: "0b11: Compressed source and destination ports",
}

THR_NHCEXT_IDENTIFIERS = {
    0: "0b000: IPv6 Hop-by-Hop Options Header",
    1: "0b001: IPv6 Routing Header",
    2: "0b010: IPv6 Fragment Header",
    3: "0b011: IPv6 Destination Options Header",
    4: "0b100: IPv6 Mobility Header",
    7: "0b111: IPv6 Header",
}


def thr_fields(pkt, msg_queue):
    """Parse Thread fields."""
    if config.row["mac_frametype"].startswith("0b000:"):
        thr_beacon(pkt)
        return
    elif not config.row["mac_frametype"].startswith("0b001:"):
        msg_obj = "Packet #{} in {} contains unknown Thread fields".format(
            config.row["pkt_num"],
            config.row["pcap_filename"],
        )
        if msg_queue is None:
            logging.debug(msg_obj)
        else:
            msg_queue.put((Message.DEBUG, msg_obj))
        config.row["error_msg"] = "Unknown Thread fields"
        return

    for curr_layer in pkt.layers():
        if curr_layer in {CookedLinux, Dot15d4, Dot15d4FCS, Dot15d4Data}:
            continue
        elif curr_layer == LoWPANMesh:
            thr_mesh(pkt, msg_queue)
            return
        elif curr_layer == LoWPANFragmentationFirst:
            thr_firstfrag(pkt, msg_queue)
            return
        elif curr_layer == LoWPANFragmentationSubsequent:
            thr_subseqfrag(pkt)
            return
        elif curr_layer == LoWPAN_IPHC:
            thr_iphc(pkt, msg_queue)
            return
        else:
            config.row["error_msg"] = "Unable to parse {}".format(curr_layer)
            return


def thr_beacon(pkt):
    # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-thread.c#L3293-3315
    # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-thread.c#L2147-2169
    config.row["thr_beacon_protocolid"] = pkt[ThreadBeacon].protocol_id
    config.row["thr_beacon_version"] = pkt[ThreadBeacon].version
    config.row["thr_beacon_native"] = pkt[ThreadBeacon].native
    config.row["thr_beacon_joining"] = pkt[ThreadBeacon].joining
    config.row["thr_beacon_networkname"] = str(
        pkt[ThreadBeacon].network_name,
        encoding="utf-8",
    ).rstrip("\0")
    config.row["thr_beacon_epid"] = format(
        pkt[ThreadBeacon].extended_pan_id,
        "016x",
    )

    # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-thread.c#L2171-2174
    if len(bytes(pkt[ThreadBeacon].payload)) > 0:
        config.row["thr_beacon_payload"] = (
            bytes(pkt[ThreadBeacon].payload).hex()
        )


# https://doi.org/10.17487/rfc4944
def thr_mesh(pkt, msg_queue):
    # Pattern field (2 bits)
    config.row["thr_mesh_pattern"] = pkt[LoWPANMesh].reserved
    if config.row["thr_mesh_pattern"] != 0b10:
        config.row["error_msg"] = "Unexpected mesh pattern value"
        return
    # VF field (1 bit)
    if not (
        config.update_row(
            "thr_mesh_vf",
            pkt[LoWPANMesh].v,
            THR_VF_MODES,
            "Unknown mesh VF mode",
        )
    ):
        return
    # FD field (1 bit)
    if not (
        config.update_row(
            "thr_mesh_fd",
            pkt[LoWPANMesh].f,
            THR_FD_MODES,
            "Unknown mesh FD mode",
        )
    ):
        return
    # Hops Left field (4 bits)
    config.row["thr_mesh_hopsleft"] = pkt[LoWPANMesh].hopsLeft
    # Deep Hops Left field (0/8 bits)
    if config.row["thr_mesh_hopsleft"] == 0b1111:
        config.row["thr_mesh_deephopsleft"] = pkt[LoWPANMesh].deepHopsLeft
    # Very First Address field (16/64 bits)
    if config.row["thr_mesh_vf"].startswith("0b1:"):
        config.row["thr_mesh_srcshortaddr"] = "0x{:04x}".format(
            pkt[LoWPANMesh].src,
        )
    elif config.row["thr_mesh_vf"].startswith("0b0:"):
        config.row["thr_mesh_srcextendedaddr"] = format(
            pkt[LoWPANMesh].src,
            "016x",
        )
    else:
        config.row["error_msg"] = "Invalid mesh VF mode"
        return
    # Final Destination Address field (16/64 bits)
    if config.row["thr_mesh_fd"].startswith("0b1:"):
        config.row["thr_mesh_dstshortaddr"] = "0x{:04x}".format(
            pkt[LoWPANMesh].dst,
        )
    elif config.row["thr_mesh_fd"].startswith("0b0:"):
        config.row["thr_mesh_dstextendedaddr"] = format(
            pkt[LoWPANMesh].dst,
            "016x",
        )
    else:
        config.row["error_msg"] = "Invalid mesh FD mode"
        return

    if len(bytes(pkt[LoWPANMesh].payload)) > 0:
        if type(pkt[LoWPANMesh].payload) == LoWPAN_IPHC:
            thr_iphc(pkt, msg_queue)
            return
        else:
            config.row["error_msg"] = (
                "Unexpected mesh payload type: {}".format(
                    type(pkt[LoWPANMesh].payload),
                )
            )
            return
    else:
        config.row["error_msg"] = "Unexpected lack of mesh payload"
        return


# https://doi.org/10.17487/rfc4944
def thr_firstfrag(pkt, msg_queue):
    # Pattern field (5 bits)
    config.row["thr_firstfrag_pattern"] = (
        pkt[LoWPANFragmentationFirst].reserved
    )
    if config.row["thr_firstfrag_pattern"] != 0b11000:
        config.row["error_msg"] = "Unexpected first fragment pattern value"
        return
    # Datagram Size field (11 bits)
    config.row["thr_firstfrag_datagramsize"] = (
        pkt[LoWPANFragmentationFirst].datagramSize
    )
    # Datagram Tag field (16 bits)
    config.row["thr_firstfrag_datagramtag"] = "0x{:04x}".format(
        pkt[LoWPANFragmentationFirst].datagramTag,
    )

    if len(bytes(pkt[LoWPANFragmentationFirst].payload)) > 0:
        if type(pkt[LoWPANFragmentationFirst].payload) == Raw:
            config.row["thr_firstfrag_payload"] = (
                bytes(pkt[LoWPANFragmentationFirst].payload).hex()
            )
            return
        elif type(pkt[LoWPANFragmentationFirst].payload) == LoWPAN_IPHC:
            thr_iphc(pkt, msg_queue)
            return
        else:
            config.row["error_msg"] = (
                "Unexpected first fragment payload type: {}".format(
                    type(pkt[LoWPANFragmentationFirst].payload),
                )
            )
            return
    else:
        config.row["error_msg"] = "Unexpected lack of first fragment payload"
        return


# https://doi.org/10.17487/rfc4944
def thr_subseqfrag(pkt):
    # Pattern field (5 bits)
    config.row["thr_subseqfrag_pattern"] = (
        pkt[LoWPANFragmentationSubsequent].reserved
    )
    if config.row["thr_subseqfrag_pattern"] != 0b11100:
        config.row["error_msg"] = (
            "Unexpected subsequent fragment pattern value"
        )
        return
    # Datagram Size field (11 bits)
    config.row["thr_subseqfrag_datagramsize"] = (
        pkt[LoWPANFragmentationSubsequent].datagramSize
    )
    # Datagram Tag field (16 bits)
    config.row["thr_subseqfrag_datagramtag"] = "0x{:04x}".format(
        pkt[LoWPANFragmentationSubsequent].datagramTag,
    )
    # Datagram Offset field (8 bits)
    config.row["thr_subseqfrag_datagramoffset"] = (
        pkt[LoWPANFragmentationSubsequent].datagramOffset
    )

    if len(bytes(pkt[LoWPANFragmentationSubsequent].payload)) > 0:
        if type(pkt[LoWPANFragmentationSubsequent].payload) == Raw:
            config.row["thr_subseqfrag_payload"] = (
                bytes(pkt[LoWPANFragmentationSubsequent].payload).hex()
            )
            return
        else:
            config.row["error_msg"] = (
                "Unexpected subsequent fragment payload type: {}".format(
                    type(pkt[LoWPANFragmentationSubsequent].payload),
                )
            )
            return
    else:
        config.row["error_msg"] = (
            "Unexpected lack of subsequent fragment payload"
        )
        return


# https://doi.org/10.17487/rfc6282
def thr_iphc(pkt, msg_queue):
    # Pattern field (3 bits)
    config.row["thr_iphc_pattern"] = pkt[LoWPAN_IPHC].reserved
    if config.row["thr_iphc_pattern"] != 0b011:
        config.row["error_msg"] = "Unexpected IPHC pattern value"
        return
    # TF field (2 bits)
    if not (
        config.update_row(
            "thr_iphc_tf",
            pkt[LoWPAN_IPHC].tf,
            THR_TF_MODES,
            "Unknown IPHC TF mode",
        )
    ):
        return
    # NH field (1 bit)
    if not (
        config.update_row(
            "thr_iphc_nh",
            pkt[LoWPAN_IPHC].nh,
            THR_NH_MODES,
            "Unknown IPHC NH mode",
        )
    ):
        return
    # HLIM field (2 bits)
    if not (
        config.update_row(
            "thr_iphc_hlim",
            pkt[LoWPAN_IPHC].hlim,
            THR_HLIM_MODES,
            "Unknown IPHC HLIM mode",
        )
    ):
        return
    # CID field (1 bit)
    if not (
        config.update_row(
            "thr_iphc_cid",
            pkt[LoWPAN_IPHC].cid,
            THR_CID_STATES,
            "Unknown IPHC CID state",
        )
    ):
        return
    # SAC field (1 bit)
    if not (
        config.update_row(
            "thr_iphc_sac",
            pkt[LoWPAN_IPHC].sac,
            THR_SAC_STATES,
            "Unknown IPHC SAC state",
        )
    ):
        return
    # SAM field (2 bits)
    if config.row["thr_iphc_sac"].startswith("0b0:"):
        if not (
            config.update_row(
                "thr_iphc_sam",
                pkt[LoWPAN_IPHC].sam,
                THR_STATELESS_SOURCE_ADDRESS_MODES,
                "Unknown IPHC stateless source address mode",
            )
        ):
            return
    elif config.row["thr_iphc_sac"].startswith("0b1:"):
        if not (
            config.update_row(
                "thr_iphc_sam",
                pkt[LoWPAN_IPHC].sam,
                THR_STATEFUL_SOURCE_ADDRESS_MODES,
                "Unknown IPHC stateful source address mode",
            )
        ):
            return
    else:
        config.row["error_msg"] = "Invalid IPHC SAC state"
        return
    # Multicast field (1 bit)
    if not (
        config.update_row(
            "thr_iphc_multicast",
            pkt[LoWPAN_IPHC].m,
            THR_MULTICAST_STATES,
            "Unknown IPHC multicast state",
        )
    ):
        return
    # DAC field (1 bit)
    if not (
        config.update_row(
            "thr_iphc_dac",
            pkt[LoWPAN_IPHC].dac,
            THR_DAC_STATES,
            "Unknown IPHC DAC state",
        )
    ):
        return
    # DAM field (2 bits)
    if config.row["thr_iphc_multicast"].startswith("0b0:"):
        if config.row["thr_iphc_dac"].startswith("0b0:"):
            if not (
                config.update_row(
                    "thr_iphc_dam",
                    pkt[LoWPAN_IPHC].dam,
                    THR_STATELESS_UNICAST_DESTINATION_ADDRESS_MODES,
                    "Unknown IPHC stateless unicast destination address mode",
                )
            ):
                return
        elif config.row["thr_iphc_dac"].startswith("0b1:"):
            if not (
                config.update_row(
                    "thr_iphc_dam",
                    pkt[LoWPAN_IPHC].dam,
                    THR_STATEFUL_UNICAST_DESTINATION_ADDRESS_MODES,
                    "Unknown IPHC stateful unicast destination address mode",
                )
            ):
                return
        else:
            config.row["error_msg"] = "Invalid IPHC DAC state"
            return
    elif config.row["thr_iphc_multicast"].startswith("0b1:"):
        if config.row["thr_iphc_dac"].startswith("0b0:"):
            if not (
                config.update_row(
                    "thr_iphc_dam",
                    pkt[LoWPAN_IPHC].dam,
                    THR_STATELESS_MULTICAST_DESTINATION_ADDRESS_MODES,
                    "Unknown IPHC stateless multicast "
                    + "destination address mode",
                )
            ):
                return
        elif config.row["thr_iphc_dac"].startswith("0b1:"):
            if not (
                config.update_row(
                    "thr_iphc_dam",
                    pkt[LoWPAN_IPHC].dam,
                    THR_STATEFUL_MULTICAST_DESTINATION_ADDRESS_MODES,
                    "Unknown IPHC stateful multicast "
                    + "destination address mode",
                )
            ):
                return
        else:
            config.row["error_msg"] = "Invalid IPHC DAC state"
            return
    else:
        config.row["error_msg"] = "Invalid IPHC multicast state"
        return

    if config.row["thr_iphc_cid"].startswith("0b1:"):
        # Source Context Identifier field (4 bits)
        config.row["thr_iphc_sci"] = pkt[LoWPAN_IPHC].sci
        # Destination Context Identifier field (4 bits)
        config.row["thr_iphc_dci"] = pkt[LoWPAN_IPHC].dci
    elif not config.row["thr_iphc_cid"].startswith("0b0:"):
        config.row["error_msg"] = "Invalid IPHC CID state"
        return

    if config.row["thr_iphc_tf"].startswith("0b00:"):
        # ECN field (2 bits)
        config.row["thr_iphc_ecn"] = pkt[LoWPAN_IPHC].tc_ecn
        # DSCP field (6 bits)
        config.row["thr_iphc_dscp"] = pkt[LoWPAN_IPHC].tc_dscp
        # FL field (6 bits)
        config.row["thr_iphc_fl"] = pkt[LoWPAN_IPHC].flowlabel
    elif config.row["thr_iphc_tf"].startswith("0b01:"):
        # ECN field (2 bits)
        config.row["thr_iphc_ecn"] = pkt[LoWPAN_IPHC].tc_ecn
        # FL field (6 bits)
        config.row["thr_iphc_fl"] = pkt[LoWPAN_IPHC].flowlabel
    elif config.row["thr_iphc_tf"].startswith("0b10:"):
        # ECN field (2 bits)
        config.row["thr_iphc_ecn"] = pkt[LoWPAN_IPHC].tc_ecn
        # DSCP field (6 bits)
        config.row["thr_iphc_dscp"] = pkt[LoWPAN_IPHC].tc_dscp
    elif not config.row["thr_iphc_tf"].startswith("0b11:"):
        config.row["error_msg"] = "Invalid IPHC TF mode"
        return

    if config.row["thr_iphc_nh"].startswith("0b0:"):
        # Next Header field (8 bits)
        config.row["thr_iphc_nextheader"] = pkt[LoWPAN_IPHC].nhField
    elif not config.row["thr_iphc_nh"].startswith("0b1:"):
        config.row["error_msg"] = "Invalid IPHC NH mode"
        return

    if config.row["thr_iphc_hlim"].startswith("0b00:"):
        # Hop Limit field (8 bits)
        config.row["thr_iphc_hoplimit"] = pkt[LoWPAN_IPHC].hopLimit
    elif not (
        config.row["thr_iphc_hlim"].startswith("0b01:")
        or config.row["thr_iphc_hlim"].startswith("0b10:")
        or config.row["thr_iphc_hlim"].startswith("0b11:")
    ):
        config.row["error_msg"] = "Invalid IPHC HLIM mode"
        return

    # Source Address field (0/16/64/128 bits)
    if config.row["thr_iphc_sac"].startswith("0b0:"):
        if (
            config.row["thr_iphc_sam"].startswith("0b00:")
            or config.row["thr_iphc_sam"].startswith("0b01:")
            or config.row["thr_iphc_sam"].startswith("0b10:")
        ):
            config.row["thr_iphr_src"] = pkt[LoWPAN_IPHC].src
        elif not config.row["thr_iphc_sam"].startswith("0b11:"):
            config.row["error_msg"] = (
                "Invalid IPHC stateless source address mode"
            )
    elif config.row["thr_iphc_sac"].startswith("0b1:"):
        if (
            config.row["thr_iphc_sam"].startswith("0b01:")
            or config.row["thr_iphc_sam"].startswith("0b10:")
        ):
            config.row["thr_iphr_src"] = pkt[LoWPAN_IPHC].src
        elif not (
            config.row["thr_iphc_sam"].startswith("0b00:")
            or config.row["thr_iphc_sam"].startswith("0b11:")
        ):
            config.row["error_msg"] = (
                "Invalid IPHC stateless source address mode"
            )
    else:
        config.row["error_msg"] = "Invalid IPHC SAC state"
        return

    # Destination Address field (0/8/16/32/48/64/128 bits)
    if config.row["thr_iphc_multicast"].startswith("0b0:"):
        if config.row["thr_iphc_dac"].startswith("0b0:"):
            if (
                config.row["thr_iphc_dam"].startswith("0b00:")
                or config.row["thr_iphc_dam"].startswith("0b01:")
                or config.row["thr_iphc_dam"].startswith("0b10:")
            ):
                config.row["thr_iphr_dst"] = pkt[LoWPAN_IPHC].dst
            elif not config.row["thr_iphc_dam"].startswith("0b11:"):
                config.row["error_msg"] = (
                    "Invalid IPHC stateless unicast destination address mode",
                )
        elif config.row["thr_iphc_dac"].startswith("0b1:"):
            if (
                config.row["thr_iphc_dam"].startswith("0b01:")
                or config.row["thr_iphc_dam"].startswith("0b10:")
            ):
                config.row["thr_iphr_dst"] = pkt[LoWPAN_IPHC].dst
            elif config.row["thr_iphc_dam"].startswith("0b00:"):
                config.row["error_msg"] = (
                    "Unexpected IPHC stateful unicast "
                    + "destination address mode",
                )
            elif not config.row["thr_iphc_dam"].startswith("0b11:"):
                config.row["error_msg"] = (
                    "Invalid IPHC stateful unicast destination address mode",
                )
        else:
            config.row["error_msg"] = "Invalid IPHC DAC state"
            return
    elif config.row["thr_iphc_multicast"].startswith("0b1:"):
        if config.row["thr_iphc_dac"].startswith("0b0:"):
            if (
                config.row["thr_iphc_dam"].startswith("0b00:")
                or config.row["thr_iphc_dam"].startswith("0b01:")
                or config.row["thr_iphc_dam"].startswith("0b10:")
                or config.row["thr_iphc_dam"].startswith("0b11:")
            ):
                config.row["thr_iphr_dst"] = pkt[LoWPAN_IPHC].dst
            else:
                config.row["error_msg"] = (
                    "Invalid IPHC stateless multicast "
                    + "destination address mode",
                )
        elif config.row["thr_iphc_dac"].startswith("0b1:"):
            if config.row["thr_iphc_dam"].startswith("0b00:"):
                config.row["thr_iphr_dst"] = pkt[LoWPAN_IPHC].dst
            elif (
                config.row["thr_iphc_dam"].startswith("0b01:")
                or config.row["thr_iphc_dam"].startswith("0b10:")
                or config.row["thr_iphc_dam"].startswith("0b11:")
            ):
                config.row["error_msg"] = (
                    "Unexpected IPHC stateful multicast "
                    + "destination address mode",
                )
            else:
                config.row["error_msg"] = (
                    "Invalid IPHC stateful multicast "
                    + "destination address mode",
                )
        else:
            config.row["error_msg"] = "Invalid IPHC DAC state"
            return
    else:
        config.row["error_msg"] = "Invalid IPHC multicast state"
        return

    if len(bytes(pkt[LoWPAN_IPHC].payload)) > 0:
        if config.row["thr_iphc_nh"].startswith("0b1:"):
            if type(pkt[LoWPAN_IPHC].payload) == LoWPAN_NHC:
                thr_nhc(pkt, msg_queue)
                return
            else:
                config.row["error_msg"] = (
                    "Unexpected IPHC payload type: {}".format(
                        type(pkt[LoWPAN_IPHC].payload),
                    )
                )
                return
        elif config.row["thr_iphc_nh"].startswith("0b0:"):
            if type(pkt[LoWPAN_IPHC].payload) == IPv6:
                thr_decompipv6(pkt, msg_queue)
                return
            elif (
                type(pkt[LoWPAN_IPHC].payload) == Raw
                and config.row["thr_firstfrag_pattern"] is not None
            ):
                config.row["thr_firstfrag_payload"] = (
                    bytes(pkt[LoWPAN_IPHC].payload).hex()
                )
                return
            else:
                config.row["error_msg"] = (
                    "Unexpected IPHC payload type: {}".format(
                        type(pkt[LoWPAN_IPHC].payload),
                    )
                )
                return
        else:
            config.row["error_msg"] = "Invalid IPHC NH mode"
            return
    else:
        config.row["error_msg"] = "Unexpected lack of IPHC payload"
        return


# https://doi.org/10.17487/rfc6282
def thr_nhc(pkt, msg_queue):
    if len(pkt[LoWPAN_NHC].exts) == 0:
        config.row["error_msg"] = "Unexpected lack of NHC headers"
        return

    for nhc_header in pkt[LoWPAN_NHC].exts:
        if type(nhc_header) == LoWPAN_NHC_IPv6Ext:
            if config.row["thr_nhcext_pattern"] is not None:
                config.row["error_msg"] = "Duplicate NHC EXT pattern"
                return
            # Pattern field (4 bits)
            config.row["thr_nhcext_pattern"] = nhc_header.res
            if config.row["thr_nhcext_pattern"] != 0b1110:
                config.row["error_msg"] = "Unexpected NHC EXT pattern value"
                return
            # IPv6 Extension Header ID field (3 bits)
            if not (
                config.update_row(
                    "thr_nhcext_id",
                    nhc_header.eid,
                    THR_NHCEXT_IDENTIFIERS,
                    "Unknown NHC EXT identifier",
                )
            ):
                return
            # NH field (1 bit)
            if not (
                config.update_row(
                    "thr_nhcext_nh",
                    nhc_header.nh,
                    THR_NH_MODES,
                    "Unknown NHC EXT NH mode",
                )
            ):
                return
            if config.row["thr_nhcext_nh"].startswith("0b0:"):
                # Next Header field (8 bits)
                config.row["thr_nhcext_nextheader"] = nhc_header.nhField
            elif not config.row["thr_iphc_nh"].startswith("0b1:"):
                config.row["error_msg"] = "Invalid NHC EXT NH mode"
                return
            # Length field (8 bits)
            config.row["thr_nhcext_length"] = nhc_header.len
            # Data field (variable)
            config.row["thr_nhcext_data"] = nhc_header.data.hex()
        elif type(nhc_header) == LoWPAN_NHC_UDP:
            if config.row["thr_nhcudp_pattern"] is not None:
                config.row["error_msg"] = "Duplicate NHC UDP pattern"
                return
            # Pattern field (5 bits)
            config.row["thr_nhcudp_pattern"] = nhc_header.res
            if config.row["thr_nhcudp_pattern"] != 0b11110:
                config.row["error_msg"] = "Unexpected NHC UDP pattern value"
                return
            # Checksum Mode field (1 bit)
            if not (
                config.update_row(
                    "thr_nhcudp_cm",
                    nhc_header.C,
                    THR_NHCUDP_CHECKSUM_MODES,
                    "Unknown NHC UDP checksum mode",
                )
            ):
                return
            # Ports Mode field (2 bits)
            if not (
                config.update_row(
                    "thr_nhcudp_pm",
                    nhc_header.P,
                    THR_NHCUDP_PORTS_MODES,
                    "Unknown NHC UDP ports mode",
                )
            ):
                return
            # Source Port field (4/8/16 bits)
            config.row["thr_nhcudp_sport"] = nhc_header.udpSourcePort
            # Destination Port field (4/8/16 bits)
            config.row["thr_nhcudp_dport"] = nhc_header.udpDestPort
            if config.row["thr_nhcudp_cm"].startswith("0b0:"):
                # Checksum field (16 bits)
                config.row["thr_nhcudp_checksum"] = "0x{:04x}".format(
                    nhc_header.udpChecksum,
                )
            elif not config.row["thr_nhcudp_cm"].startswith("0b1:"):
                config.row["error_msg"] = "Invalid NHC UDP checksum mode"
                return
        else:
            config.row["error_msg"] = "Unexpected NHC header type: {}".format(
                type(nhc_header),
            )
            return

    if len(bytes(pkt[LoWPAN_NHC].payload)) > 0:
        if type(pkt[LoWPAN_NHC].payload) == IPv6:
            thr_decompipv6(pkt, msg_queue)
            return
        elif (
            type(pkt[LoWPAN_NHC].payload) == Raw
            and config.row["thr_firstfrag_pattern"] is not None
        ):
            config.row["thr_firstfrag_payload"] = (
                bytes(pkt[LoWPAN_NHC].payload).hex()
            )
            return
        else:
            config.row["error_msg"] = (
                "Unexpected NHC payload type: {}".format(
                    type(pkt[LoWPAN_NHC].payload),
                )
            )
            return
    else:
        config.row["error_msg"] = "Unexpected lack of NHC payload"
        return


# https://doi.org/10.17487/rfc2460
def thr_decompipv6(pkt, msg_queue):
    # Version field (4 bits)
    config.row["thr_decompipv6_version"] = pkt[IPv6].version

    # Traffic Class field (8 bits)
    config.row["thr_decompipv6_tc"] = pkt[IPv6].tc

    # Flow Label field (20 bits)
    config.row["thr_decompipv6_fl"] = pkt[IPv6].fl

    # Payload Length field (16 bits)
    config.row["thr_decompipv6_plen"] = pkt[IPv6].plen

    # Next Header field (8 bits)
    config.row["thr_decompipv6_nh"] = pkt[IPv6].nh

    # Hop Limit field (8 bits)
    config.row["thr_decompipv6_hlim"] = pkt[IPv6].hlim

    # Source Address field (128 bits)
    config.row["thr_decompipv6_src"] = pkt[IPv6].src

    # Destination Address field (128 bits)
    config.row["thr_decompipv6_dst"] = pkt[IPv6].dst

    if len(bytes(pkt[IPv6].payload)) > 0:
        if config.row["thr_decompipv6_nh"] == 58:
            config.row["thr_decompicmpv6"] = bytes(pkt[IPv6].payload).hex()
            return
        elif config.row["thr_decompipv6_nh"] == 17:
            if type(pkt[IPv6].payload) == UDP:
                thr_decompudp(pkt, msg_queue)
                return
            else:
                config.row["error_msg"] = (
                    "Unexpected decompressed IPv6 payload type: {}".format(
                        type(pkt[IPv6].payload),
                    )
                )
                return
        else:
            config.row["error_msg"] = (
                "Unable to parse the next header "
                + "of the decompressed IPv6 header "
                + "based on its assigned number: {}".format(
                    config.row["thr_decompipv6_nh"],
                )
            )
            return
    else:
        config.row["error_msg"] = (
            "Unexpected lack of decompressed IPv6 payload"
        )
        return


# https://doi.org/10.17487/rfc0768
def thr_decompudp(pkt, msg_queue):
    # Source Port field (16 bits)
    config.row["thr_decompudp_sport"] = pkt[UDP].sport

    # Destination Port field (16 bits)
    config.row["thr_decompudp_dport"] = pkt[UDP].dport

    # Length field (16 bits)
    config.row["thr_decompudp_length"] = pkt[UDP].len

    # Checksum field (16 bits)
    config.row["thr_decompudp_checksum"] = "0x{:04x}".format(pkt[UDP].chksum)

    if len(bytes(pkt[UDP].payload)) > 0:
        config.row["thr_decompudp_payload"] = bytes(pkt[UDP].payload).hex()

        tmp_frame = (
            IPv6(
                version=config.row["thr_decompipv6_version"],
                tc=config.row["thr_decompipv6_tc"],
                fl=config.row["thr_decompipv6_fl"],
                nh=config.row["thr_decompipv6_nh"],
                hlim=config.row["thr_decompipv6_hlim"],
                src=config.row["thr_decompipv6_src"],
                dst=config.row["thr_decompipv6_dst"],
            )
            / UDP(
                sport=config.row["thr_decompudp_sport"],
                dport=config.row["thr_decompudp_dport"],
            )
            / Raw(
                bytes.fromhex(config.row["thr_decompudp_payload"]),
            )
        )
        tmp_frame = IPv6(bytes(tmp_frame))
        if (
            config.row["thr_decompudp_checksum"]
            != "0x{:04x}".format(tmp_frame[UDP].chksum)
        ):
            config.row["warning_msg"] = "Incorrect UDP checksum"

        # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-mle.c#L152
        if (
            config.row["thr_decompudp_sport"] == 19788
            and config.row["thr_decompudp_dport"] == 19788
        ):

            if type(pkt[UDP].payload) == MLE:
                mle_fields(pkt, msg_queue)
                return
            else:
                config.row["error_msg"] = (
                    "Unexpected UDP payload type: {}".format(
                        type(pkt[UDP].payload),
                    )
                )
                return
    else:
        config.row["error_msg"] = (
            "Unexpected lack of decompressed UDP payload"
        )
        return
