# Copyright (C) 2021 Dimitrios-Georgios Akestoridis
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

from .. import config


def basic_information():
    row_data = {
        "pkt_time": "{:.6f}".format(config.entry["pkt_time"]),
        "phy_length": config.entry["phy_length"],
        "mac_frametype": config.entry["mac_frametype"],
        "mac_seqnum": config.entry["mac_seqnum"],
        "nwk_seqnum": config.entry["nwk_seqnum"],
        "nwk_aux_framecounter": config.entry["nwk_aux_framecounter"],
        "der_same_macnwksrc": config.entry["der_same_macnwksrc"],
        "der_mac_srcpanid": config.entry["der_mac_srcpanid"],
        "der_mac_srcshortaddr": config.entry["der_mac_srcshortaddr"],
        "der_mac_srcextendedaddr": config.entry["der_mac_srcextendedaddr"],
        "error_msg": config.entry["error_msg"],
    }
    config.db.insert("basic_information", row_data)


def battery_percentage():
    if (config.entry["error_msg"] is None
            and (config.entry["der_same_macnwksrc"]
                 == "Same MAC/NWK Src: True")
            and (config.entry["aps_frametype"]
                 == "0b00: APS Data")
            and (config.entry["aps_profile_id"]
                 == "0x0104: Zigbee Home Automation (ZHA)")
            and (config.entry["aps_cluster_id"]
                 == "0x0001: Power Configuration")):
        if config.entry["zcl_cmd_id"] == "0x01: Read Attributes Response":
            identifiers = config.entry[
                "zcl_readattributesresponse_identifiers"].split(",")
            statuses = config.entry[
                "zcl_readattributesresponse_statuses"].split(",")
            datatypes = config.entry[
                "zcl_readattributesresponse_datatypes"].split(",")
            values = config.entry[
                "zcl_readattributesresponse_values"].split(",")
            if (len(identifiers) != len(statuses)
                    or len(identifiers) != len(datatypes)
                    or len(identifiers) != len(values)):
                return
            row_data = {
                "pkt_time": "{:.6f}".format(config.entry["pkt_time"]),
                "srcpanid": config.entry["der_mac_srcpanid"],
                "srcshortaddr": config.entry["der_mac_srcshortaddr"],
            }
            for i in range(len(identifiers)):
                if (identifiers[i] == "0x0021"
                        and statuses[i] == "0x00: SUCCESS"
                        and datatypes[i] == "0x20: Unsigned 8-bit integer"):
                    row_data["percentage"] = int(values[i], 16) / 2.0
                    config.db.insert("battery_percentages", row_data)
                    return
        elif config.entry["zcl_cmd_id"] == "0x0a: Report Attributes":
            identifiers = config.entry[
                "zcl_reportattributes_identifiers"].split(",")
            datatypes = config.entry[
                "zcl_reportattributes_datatypes"].split(",")
            data = config.entry[
                "zcl_reportattributes_data"].split(",")
            if (len(identifiers) != len(datatypes)
                    or len(identifiers) != len(data)):
                return
            row_data = {
                "pkt_time": "{:.6f}".format(config.entry["pkt_time"]),
                "srcpanid": config.entry["der_mac_srcpanid"],
                "srcshortaddr": config.entry["der_mac_srcshortaddr"],
            }
            for i in range(len(identifiers)):
                if (identifiers[i] == "0x0021"
                        and datatypes[i] == "0x20: Unsigned 8-bit integer"):
                    row_data["percentage"] = int(data[i], 16) / 2.0
                    config.db.insert("battery_percentages", row_data)
                    return
