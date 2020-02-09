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

import os

from .. import config


COLUMN_MATCHES = set([
    (
        "phy_length--frametype.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "phy_length--frametype_cmdid.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
        "nwk_frametype",
        "nwk_cmd_id",
        "aps_frametype",
        "aps_cmd_id",
        "aps_profilename",
        "aps_clustername",
        "zcl_frametype",
        "zcl_cmd_id",
    ),
    (
        "phy_length--nwk_cmd_id.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_radius--nwk_cmd_id.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_cmd_id--phy_length.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "phy_length",
    ),
    (
        "nwk_cmd_id--nwk_radius.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_radius",
    ),
    (
        "nwk_cmd_id--pcap_filename.tsv",
        (
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "pcap_filename",
    ),
    (
        "nwk_security--nwk_cmd_id.tsv",
        (
            "nwk_security",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "nwk_cmd_id",
    ),
    (
        "phy_length-nwk_cmd_id--pcap_filename.tsv",
        (
            "phy_length",
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        "pcap_filename"
    ),
])


def custom_sorter(var_value):
    str_repr = []
    for i in range(len(var_value)):
        if var_value[i] is None:
            str_repr.append("")
        elif isinstance(var_value[i], int):
            str_repr.append(str(var_value[i]).zfill(10))
        else:
            str_repr.append(var_value[i].zfill(80))
    return ", ".join(str_repr)


def distinct_matches(out_dirpath):
    """Compute matching values under some conditions in the database table."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    for column_match in COLUMN_MATCHES:
        # Derive the path of the output file, the varying columns,
        # the matching conditions, and the list of column names
        out_filepath = os.path.join(out_dirpath, column_match[0])
        var_columns = column_match[1]
        conditions = column_match[2]
        column_names = list(column_match[3:])

        # Compute the distinct values of the varying columns
        var_values = config.distinct_values(var_columns, conditions)
        var_values.sort(key=custom_sorter)

        # Compute the distinct matches for each value
        results = []
        for var_value in var_values:
            var_conditions = list(conditions)
            for i in range(len(var_value)):
                var_conditions.append((var_columns[i], var_value[i]))
            matches = config.distinct_values(column_names, var_conditions)
            results.append((var_value, matches))

        # Write the distinct matches in the output file
        config.write_tsv(results, out_filepath)
