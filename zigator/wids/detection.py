# Copyright (C) 2021-2022 Dimitrios-Georgios Akestoridis
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

from .. import (
    config,
    crypto,
)
from ..enums import Table


def panid_conflict(panid, epid):
    if (
        config.row["error_msg"] is None
        and config.row["mac_frametype"] == "0b000: MAC Beacon"
        and config.row["mac_srcpanid"] == panid
        and config.row["nwk_beacon_epid"] != epid
    ):
        row_data = {
            "pkt_time": "{:.6f}".format(config.row["pkt_time"]),
            "description": "Potential PAN ID conflict",
        }
        config.db.insert(Table.EVENTS.value, row_data)


def unsecured_rejoinreq(panid):
    if (
        config.row["error_msg"] is None
        and config.row["mac_frametype"] == "0b001: MAC Data"
        and config.row["mac_dstpanid"] == panid
        and config.row["nwk_frametype"] == "0b01: NWK Command"
        and config.row["nwk_security"] == "0b0: NWK Security Disabled"
        and config.row["nwk_cmd_id"] == "0x06: NWK Rejoin Request"
    ):
        row_data = {
            "pkt_time": "{:.6f}".format(config.row["pkt_time"]),
            "description": "Unsecured rejoin request",
        }
        config.db.insert(Table.EVENTS.value, row_data)


def key_leakage(panid, link_key_names, link_keys_lock):
    if (
        config.row["error_msg"] is None
        and config.row["mac_frametype"] == "0b001: MAC Data"
        and config.row["mac_dstpanid"] == panid
        and config.row["nwk_frametype"] == "0b00: NWK Data"
        and config.row["nwk_security"] == "0b0: NWK Security Disabled"
        and config.row["aps_frametype"] == "0b01: APS Command"
        and config.row["aps_cmd_id"] == "0x05: APS Transport Key"
    ):
        row_data = {
            "pkt_time": "{:.6f}".format(config.row["pkt_time"]),
            "description": "Potential key leakage",
        }
        if config.row["aps_security"] == "0b1: APS Security Enabled":
            potential_keys = set()
            with link_keys_lock:
                if config.row["aps_aux_keytype"] == "0b00: Data Key":
                    for name in link_key_names:
                        if name in config.link_keys.keys():
                            potential_keys.add(config.link_keys[name])
                elif (
                    config.row["aps_aux_keytype"] == "0b10: Key-Transport Key"
                ):
                    for name in link_key_names:
                        if name in config.link_keys.keys():
                            potential_keys.add(
                                crypto.zigbee_hmac(
                                    bytes.fromhex("00"),
                                    config.link_keys[name],
                                ),
                            )
                elif config.row["aps_aux_keytype"] == "0b11: Key-Load Key":
                    for name in link_key_names:
                        if name in config.link_keys.keys():
                            potential_keys.add(
                                crypto.zigbee_hmac(
                                    bytes.fromhex("02"),
                                    config.link_keys[name],
                                ),
                            )
            for key in potential_keys:
                if config.row["aps_aux_deckey"] == key.hex():
                    config.db.insert(Table.EVENTS.value, row_data)
                    return
        else:
            config.db.insert(Table.EVENTS.value, row_data)


def low_battery(panid):
    if (
        config.row["error_msg"] is None
        and config.row["mac_frametype"] == "0b001: MAC Data"
        and config.row["mac_srcaddrmode"] == "0b10: Short source MAC address"
        and config.row["mac_dstpanid"] == panid
        and config.row["nwk_frametype"] == "0b00: NWK Data"
        and config.row["nwk_srcshortaddr"] == config.row["mac_srcshortaddr"]
        and config.row["aps_frametype"] == "0b00: APS Data"
        and (
            config.row["aps_profile_id"]
            == "0x0104: Zigbee Home Automation (ZHA)"
        )
        and config.row["aps_cluster_id"] == "0x0500: IAS Zone"
    ):
        row_data = {
           "pkt_time": "{:.6f}".format(config.row["pkt_time"]),
           "description": "Low battery report from the {} node".format(
               config.row["nwk_srcshortaddr"]),
        }
        if config.row["zcl_cmd_id"] == "0x01: Read Attributes Response":
            identifiers = config.row[
                "zcl_readattributesresponse_identifiers"
            ].split(",")
            statuses = config.row[
                "zcl_readattributesresponse_statuses"
            ].split(",")
            datatypes = config.row[
                "zcl_readattributesresponse_datatypes"
            ].split(",")
            values = config.row[
                "zcl_readattributesresponse_values"
            ].split(",")
            if (
                len(identifiers) != len(statuses)
                or len(identifiers) != len(datatypes)
                or len(identifiers) != len(values)
            ):
                return
            for i in range(len(identifiers)):
                if (
                    identifiers[i] == "0x0002"
                    and statuses[i] == "0x00: SUCCESS"
                    and datatypes[i] == "0x19: 16-bit bitmap"
                    and (
                        (
                            int.from_bytes(
                                bytes.fromhex(values[i][2:]),
                                byteorder="little",
                            )
                            >> 3
                        )
                        & 0b1
                    )
                ):
                    config.db.insert(Table.EVENTS.value, row_data)
                    return
        elif (
            config.row["zcl_cmd_id"]
            == "0x00: Zone Status Change Notification"
        ):
            zone_status = int.from_bytes(
                bytes.fromhex(
                    config.row[
                        "zcl_iaszone_zonestatuschangenotif_zonestatus"
                    ][2:],
                ),
                byteorder="little",
            )
            if (zone_status >> 3) & 0b1:
                config.db.insert(Table.EVENTS.value, row_data)


def unverified_payload(panid):
    if (
        config.row["error_msg"] is None
        and config.row["mac_frametype"] == "0b001: MAC Data"
        and config.row["mac_dstpanid"] == panid
    ):
        if (
            config.row["warning_msg"]
            == "PW301: Unable to decrypt the NWK payload"
        ):
            row_data = {
                "pkt_time": "{:.6f}".format(config.row["pkt_time"]),
                "description": "Unverified NWK payload",
            }
            config.db.insert(Table.EVENTS.value, row_data)
        elif (
            config.row["warning_msg"]
            == "PW401: Unable to decrypt the APS payload"
        ):
            row_data = {
                "pkt_time": "{:.6f}".format(config.row["pkt_time"]),
                "description": "Unverified APS payload",
            }
            config.db.insert(Table.EVENTS.value, row_data)
