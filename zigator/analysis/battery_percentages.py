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


def battery_percentages(db_filepath, out_dirpath):
    """Extract battery percentage measurements."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Initialize the dictionary of battery percentage measurements
    measurements = {}
    logging.info("Extracting battery percentage measurements...")

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
            ("aps_cluster_id", "0x0001: Power Configuration"),
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
            if identifiers[i] == "0x0021":
                if (
                    statuses[i] == "0x00: SUCCESS"
                    and datatypes[i] == "0x20: Unsigned 8-bit integer"
                ):
                    percentage = "{:.1f}".format(int(values[i], 16) / 2.0)
                    measurement = (pkt_time, percentage)
                    if srcextendedaddr not in measurements.keys():
                        measurements[srcextendedaddr] = [measurement]
                    else:
                        measurements[srcextendedaddr].append(measurement)
                break
            else:
                continue

    # Extract measurements from Report Attributes commands
    fetched_tuples = config.db.fetch_values(
        "packets",
        [
            "pkt_time",
            "zcl_reportattributes_identifiers",
            "zcl_reportattributes_datatypes",
            "zcl_reportattributes_data",
            "der_nwk_srcextendedaddr",
        ],
        [
            ("error_msg", None),
            ("der_same_macnwksrc", "Same MAC/NWK Src: True"),
            ("aps_frametype", "0b00: APS Data"),
            ("aps_profile_id", "0x0104: Zigbee Home Automation (ZHA)"),
            ("aps_cluster_id", "0x0001: Power Configuration"),
            ("zcl_cmd_id", "0x0a: Report Attributes"),
        ],
        False,
    )
    for fetched_tuple in fetched_tuples:
        pkt_time = fetched_tuple[0]
        identifiers = fetched_tuple[1].split(",")
        datatypes = fetched_tuple[2].split(",")
        data = fetched_tuple[3].split(",")
        srcextendedaddr = fetched_tuple[4]
        if (
            len(identifiers) != len(datatypes)
            or len(identifiers) != len(data)
        ):
            logging.warning("Invalid ZCL Report Attributes entries")
            continue
        for i in range(len(identifiers)):
            if identifiers[i] == "0x0021":
                if datatypes[i] == "0x20: Unsigned 8-bit integer":
                    percentage = "{:.1f}".format(int(data[i], 16) / 2.0)
                    measurement = (pkt_time, percentage)
                    if srcextendedaddr not in measurements.keys():
                        measurements[srcextendedaddr] = [measurement]
                    else:
                        measurements[srcextendedaddr].append(measurement)
                break
            else:
                continue

    # Disconnect from the provided database
    config.db.disconnect()

    # Sort the extracted measurements
    for srcextendedaddr in measurements.keys():
        measurements[srcextendedaddr].sort(key=itemgetter(0))

    # Write the battery percentage measurements in separate output files
    for srcextendedaddr in measurements.keys():
        out_filepath = os.path.join(
            out_dirpath,
            "battery-percentages-{}.tsv".format(srcextendedaddr),
        )
        config.fs.write_tsv(measurements[srcextendedaddr], out_filepath)
    logging.info(
        "Extracted battery percentage measurements of {} devices".format(
            len(measurements.keys()),
        ),
    )
