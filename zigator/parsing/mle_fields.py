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
from ipaddress import IPv6Address

from scapy.all import (
    Dot15d4AuxSecurityHeader,
    MLE,
    MLECmd,
)

from .. import (
    config,
    crypto,
)
from ..enums import Message


# https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-mle.c#L159-163
MLE_SECURITY_SUITES = {
    0: "0x00: IEEE 802.15.4 Security",
    255: "0xff: No Security",
}

MLE_SECURITY_LEVELS = {
    0: "0b000: None",
    1: "0b001: MIC-32",
    2: "0b010: MIC-64",
    3: "0b011: MIC-128",
    4: "0b100: ENC",
    5: "0b101: ENC-MIC-32",
    6: "0b110: ENC-MIC-64",
    7: "0b111: ENC-MIC-128",
}

MLE_KEY_ID_MODES = {
    0: "0b00: Implicit key determination",
    1: "0b01: Explicit key determination with the 8-byte default key source",
    2: "0b10: Explicit key determination with the 4-byte Key Source subfield",
    3: "0b11: Explicit key determination with the 8-byte Key Source subfield",
}

# https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-mle.c#L178-217
MLE_COMMAND_TYPES = {
    0: "0x00: Link Request",
    1: "0x01: Link Accept",
    2: "0x02: Link Accept and Request",
    3: "0x03: Link Reject",
    4: "0x04: Advertisement",
    5: "0x05: Update",
    6: "0x06: Update Request",
    7: "0x07: Data Request",
    8: "0x08: Data Response",
    9: "0x09: Parent Request",
    10: "0x0a: Parent Response",
    11: "0x0b: Child ID Request",
    12: "0x0c: Child ID Response",
    13: "0x0d: Child Update Request",
    14: "0x0e: Child Update Response",
    15: "0x0f: Announce",
    16: "0x10: Discovery Request",
    17: "0x11: Discovery Response",
}


def mle_fields(pkt, msg_queue):
    """Parse Mesh Link Establishment fields."""
    # Security Suite field (1 byte)
    if not (
        config.update_row(
            "mle_secsuite",
            pkt[MLE].sec_suite,
            MLE_SECURITY_SUITES,
            "Unknown MLE security suite",
        )
    ):
        return

    if config.row["mle_secsuite"].startswith("0x00:"):
        # Auxiliary Security Header field (5/6/10/14 bytes)
        if pkt.haslayer(Dot15d4AuxSecurityHeader):
            mle_auxiliary(pkt, msg_queue)
        else:
            config.row["error_msg"] = (
                "The MLE Auxiliary Security Header is not included"
            )
            return
    elif config.row["mle_secsuite"].startswith("0xff:"):
        # MLE Payload field (variable)
        if pkt.haslayer(MLECmd):
            mle_command(pkt)
        else:
            config.row["error_msg"] = "There are no MLE Command fields"
            return
    else:
        config.row["error_msg"] = "Unexpected MLE security suite"
        return


def mle_auxiliary(pkt, msg_queue):
    # Security Control field (1 byte)
    # Security Level subfield (3 bits)
    if not (
        config.update_row(
            "mle_aux_seclevel",
            pkt[MLE].aux_sec_header.sec_sc_seclevel,
            MLE_SECURITY_LEVELS,
            "Unknown MLE security level",
        )
    ):
        return
    # Key Identifier Mode subfield (2 bits)
    if not (
        config.update_row(
            "mle_aux_keyidmode",
            pkt[MLE].aux_sec_header.sec_sc_keyidmode,
            MLE_KEY_ID_MODES,
            "Unknown MLE key identifier mode",
        )
    ):
        return

    # Frame Counter field (4 bytes)
    frame_counter = pkt[MLE].aux_sec_header.sec_framecounter
    config.row["mle_aux_framecounter"] = frame_counter

    # Key Identifier field (0/1/5/9 bytes)
    potential_sources = set()
    if config.row["mle_aux_keyidmode"].startswith("0b00:"):
        if config.row["mac_srcextendedaddr"] is not None:
            potential_sources.add(int(config.row["mac_srcextendedaddr"], 16))
        potential_keys = config.mle_keys.values()
    elif config.row["mle_aux_keyidmode"].startswith("0b01:"):
        # Key Index subfield (1 byte)
        config.row["mle_aux_keyindex"] = (
            pkt[MLE].aux_sec_header.sec_keyid_keyindex
        )
        config.derive_thread_keys(config.row["mle_aux_keyindex"])
        potential_keys = config.mle_keys.values()
    elif config.row["mle_aux_keyidmode"].startswith("0b10:"):
        # Key Source subfield (4 bytes)
        config.row["mle_aux_keysource"] = format(
            pkt[MLE].aux_sec_header.sec_keyid_keysource,
            "08x",
        )
        # Key Index subfield (1 byte)
        config.row["mle_aux_keyindex"] = (
            pkt[MLE].aux_sec_header.sec_keyid_keyindex
        )
        config.derive_thread_keys(config.row["mle_aux_keyindex"])
        # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-mle.c#L392-400
        if config.row["mac_srcextendedaddr"] is not None:
            potential_sources.add(int(config.row["mac_srcextendedaddr"], 16))
        # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-thread.c#L803-809
        config.derive_thread_keys(
            config.row["mle_aux_keyindex"],
            pkt[MLE].aux_sec_header.sec_keyid_keysource,
        )
        potential_keys = config.mle_keys.values()
    elif config.row["mle_aux_keyidmode"].startswith("0b11:"):
        # Key Source subfield (8 bytes)
        config.row["mle_aux_keysource"] = format(
            pkt[MLE].aux_sec_header.sec_keyid_keysource,
            "016x",
        )
        potential_sources.add(int(config.row["mle_aux_keysource"], 16))
        # Key Index subfield (1 byte)
        config.row["mle_aux_keyindex"] = (
            pkt[MLE].aux_sec_header.sec_keyid_keyindex
        )
        config.derive_thread_keys(config.row["mle_aux_keyindex"])
        potential_keys = config.mle_keys.values()
    else:
        config.row["error_msg"] = "Invalid MLE key identifier mode"
        return

    # Attempt to decrypt the payload
    if len(potential_sources) == 0:
        potential_sources = {
            int(extendedaddr, 16)
            for extendedaddr in config.extended_addresses.keys()
        }
        if config.row["mac_srcextendedaddr"] is not None:
            potential_sources.add(int(config.row["mac_srcextendedaddr"], 16))
    # https://gitlab.com/wireshark/wireshark/-/blob/5ecb57cb9026cebf0cfa4918c4a86942620c5ecf/epan/dissectors/packet-mle.c#L461-464
    header = (
        IPv6Address(config.row["thr_decompipv6_src"]).packed
        + IPv6Address(config.row["thr_decompipv6_dst"]).packed
        + bytes(pkt[MLE].aux_sec_header)
    )
    if pkt[MLE].aux_sec_header.sec_sc_seclevel in {0, 1, 2, 3}:
        enc_payload = bytes()
        header += pkt[MLE].sec_payload
    elif pkt[MLE].aux_sec_header.sec_sc_seclevel in {4, 5, 6, 7}:
        enc_payload = pkt[MLE].sec_payload
    else:
        config.row["error_msg"] = "Unexpected MLE security level"
        return
    mic = pkt[MLE].mic
    for source_addr in potential_sources:
        for key in potential_keys:
            dec_payload, auth_payload = crypto.ieee802154_dec_ver(
                key,
                source_addr,
                frame_counter,
                pkt[MLE].aux_sec_header.sec_sc_seclevel,
                header,
                enc_payload,
                mic,
            )

            # Make sure that the decrypted payload is authentic whenever a
            # message integrity code is provided, otherwise warn that the
            # decrypted payload could not be verified
            if auth_payload or len(mic) == 0:
                if len(mic) == 0:
                    config.row["warning_msg"] = (
                        "Could not verify the decrypted MLE payload"
                    )

                config.row["mle_aux_deckey"] = key.hex()
                config.row["mle_aux_decsrc"] = format(source_addr, "016x")

                # MLE Payload field (variable)
                if pkt[MLE].aux_sec_header.sec_sc_seclevel in {0, 1, 2, 3}:
                    dec_payload = pkt[MLE].sec_payload
                elif not (
                    pkt[MLE].aux_sec_header.sec_sc_seclevel
                    in {4, 5, 6, 7}
                ):
                    config.row["error_msg"] = (
                        "Unexpected MLE security level"
                    )
                    return
                config.row["mle_aux_decpayload"] = dec_payload.hex()
                dec_pkt = MLECmd(dec_payload)
                config.row["mle_aux_decshow"] = dec_pkt.show(dump=True)
                mle_command(dec_pkt)
                return
    msg_obj = "Unable to decrypt the MLE payload of packet #{} in {}".format(
        config.row["pkt_num"],
        config.row["pcap_filename"],
    )
    if msg_queue is None:
        logging.debug(msg_obj)
    else:
        msg_queue.put((Message.DEBUG, msg_obj))
    config.row["warning_msg"] = "Unable to decrypt the MLE payload"


def mle_command(pkt):
    # Command Type field (1 byte)
    if not (
        config.update_row(
            "mle_cmd_type",
            pkt[MLECmd].cmd_type,
            MLE_COMMAND_TYPES,
            "Unknown MLE command type",
        )
    ):
        return

    # Command Payload field (variable)
    config.row["mle_cmd_payloadlength"] = len(bytes(pkt[MLECmd].payload))
    config.row["mle_cmd_payload"] = bytes(pkt[MLECmd].payload).hex()
