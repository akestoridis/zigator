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

import logging
import os

from operator import itemgetter

from .. import config


def battery_statuses(db_filepath, out_dirpath):
    """Extract battery status measurements."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Initialize the dictionary of battery status measurements
    measurements = {}
    logging.info("Extracting battery status measurements...")

    # Connect to the provided database
    config.db.connect(db_filepath)

    # Extract measurements from Read Attribute Response commands
    fetched_tuples = config.db.fetch_values(
        "packets",
        [
            "pkt_time",
            "zcl_readattributesresponse_identifiers",
            "zcl_readattributesresponse_statuses",
            "zcl_readattributesresponse_datatypes",
            "zcl_readattributesresponse_values",
            "der_nwk_srcextendedaddr",
        ],
        [
            ("error_msg", None),
            ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0104: Zigbee Home Automation (ZHA)"),
            ("aps_cluster_id", "0x0500: IAS Zone"),
            ("zcl_cmd_id", "0x01: Read Attributes Response"),
        ],
        False,
    )
    for fetched_tuple in fetched_tuples:
        pkt_time = fetched_tuple[0]
        identifiers = fetched_tuple[1].split(",")
        statuses = fetched_tuple[2].split(",")
        datatypes = fetched_tuple[3].split(",")
        values = fetched_tuple[4].split(",")
        srcextendedaddr = fetched_tuple[5]
        if (
            len(identifiers) != len(statuses)
            or len(identifiers) != len(datatypes)
            or len(identifiers) != len(values)
        ):
            logging.warning("Invalid ZCL Read Attributes Response entries")
            continue
        for i in range(len(identifiers)):
            if identifiers[i] == "0x0002":
                if (
                    statuses[i] == "0x00: SUCCESS"
                    and datatypes[i] == "0x19: 16-bit bitmap"
                ):
                    zone_status = int.from_bytes(
                        bytes.fromhex(values[i][2:]),
                        byteorder="little",
                    )
                    battery_status = (zone_status >> 3) & 0b1
                    measurement = (pkt_time, battery_status)
                    if srcextendedaddr not in measurements.keys():
                        measurements[srcextendedaddr] = [measurement]
                    else:
                        measurements[srcextendedaddr].append(measurement)
                break
            else:
                continue

    # Extract measurements from Zone Status Change Notification commands
    fetched_tuples = config.db.fetch_values(
        "packets",
        [
            "pkt_time",
            "zcl_iaszone_zonestatuschangenotif_zonestatus",
            "der_nwk_srcextendedaddr",
        ],
        [
            ("error_msg", None),
            ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0104: Zigbee Home Automation (ZHA)"),
            ("aps_cluster_id", "0x0500: IAS Zone"),
            ("zcl_cmd_id", "0x00: Zone Status Change Notification"),
        ],
        False,
    )
    for fetched_tuple in fetched_tuples:
        pkt_time = fetched_tuple[0]
        zone_status = int.from_bytes(
            bytes.fromhex(fetched_tuple[1][2:]),
            byteorder="little",
        )
        srcextendedaddr = fetched_tuple[2]
        battery_status = (zone_status >> 3) & 0b1
        measurement = (pkt_time, battery_status)
        if srcextendedaddr not in measurements.keys():
            measurements[srcextendedaddr] = [measurement]
        else:
            measurements[srcextendedaddr].append(measurement)

    # Disconnect from the provided database
    config.db.disconnect()

    # Sort the extracted measurements
    for srcextendedaddr in measurements.keys():
        measurements[srcextendedaddr].sort(key=itemgetter(0))

    # Write the battery status measurements in separate output files
    for srcextendedaddr in measurements.keys():
        out_filepath = os.path.join(
            out_dirpath,
            "battery-statuses-{}.tsv".format(srcextendedaddr),
        )
        config.fs.write_tsv(measurements[srcextendedaddr], out_filepath)
    logging.info(
        "Extracted battery status measurements of {} devices".format(
            len(measurements.keys()),
        ),
    )
