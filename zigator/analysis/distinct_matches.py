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

import logging
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
    (
        "mac_ackreq--frametype.tsv",
        (
            "mac_ackreq",
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
        "mac_ackreq--frametype_cmdid.tsv",
        (
            "mac_ackreq",
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
        "mac_dstaddrmode--frametype.tsv",
        (
            "mac_dstaddrmode",
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
        "mac_dstaddrmode--frametype_cmdid.tsv",
        (
            "mac_dstaddrmode",
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
        "mac_srcaddrmode--frametype.tsv",
        (
            "mac_srcaddrmode",
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
        "mac_srcaddrmode--frametype_cmdid.tsv",
        (
            "mac_srcaddrmode",
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
        "nwk_srcroute--frametype.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_srcroute--frametype_cmdid.tsv",
        (
            "nwk_srcroute",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
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
        "nwk_extendeddst--frametype.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_extendeddst--frametype_cmdid.tsv",
        (
            "nwk_extendeddst",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
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
        "nwk_extendedsrc--frametype.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_extendedsrc--frametype_cmdid.tsv",
        (
            "nwk_extendedsrc",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
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
        "nwk_aux_keytype--frametype.tsv",
        (
            "nwk_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("nwk_security", "NWK Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_aux_keytype--frametype_cmdid.tsv",
        (
            "nwk_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("nwk_security", "NWK Security Enabled"),
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
        "nwk_aux_extnonce--frametype.tsv",
        (
            "nwk_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("nwk_security", "NWK Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "nwk_aux_extnonce--frametype_cmdid.tsv",
        (
            "nwk_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("nwk_security", "NWK Security Enabled"),
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
        "aps_ackreq--frametype.tsv",
        (
            "aps_ackreq",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "aps_ackreq--frametype_cmdid.tsv",
        (
            "aps_ackreq",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
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
        "aps_aux_keytype--frametype.tsv",
        (
            "aps_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "aps_aux_keytype--frametype_cmdid.tsv",
        (
            "aps_aux_keytype",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
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
        "aps_aux_extnonce--frametype.tsv",
        (
            "aps_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
        ),
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "aps_aux_extnonce--frametype_cmdid.tsv",
        (
            "aps_aux_extnonce",
        ),
        (
            ("error_msg", None),
            ("aps_security", "APS Security Enabled"),
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
        "security--frametype.tsv",
        (
            "mac_security",
            "nwk_security",
            "aps_security",
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
        "security--frametype_cmdid.tsv",
        (
            "mac_security",
            "nwk_security",
            "aps_security",
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
        "srcpanid--mac_frametype_cmdid.tsv",
        (
            "mac_srcpanid",
        ),
        (
            ("error_msg", None),
        ),
        "mac_frametype",
        "mac_cmd_id",
    ),
    (
        "mac_frametype_cmdid--addrmode.tsv",
        (
            "mac_frametype",
            "mac_cmd_id",
        ),
        (
            ("error_msg", None),
        ),
        "mac_dstaddrmode",
        "mac_srcaddrmode",
    ),
    (
        "nwk_frametype_cmdid--addrmode.tsv",
        (
            "nwk_frametype",
            "nwk_cmd_id",
        ),
        (
            ("error_msg", None),
            ("!nwk_frametype", None),
        ),
        "nwk_extendeddst",
        "nwk_extendedsrc",
    ),
    (
        "nwk_srcextendedaddr--nwk_cmdid.tsv",
        (
            "nwk_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("!nwk_srcextendedaddr", None),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_dstextendedaddr--nwk_cmdid.tsv",
        (
            "nwk_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("!nwk_dstextendedaddr", None),
        ),
        "nwk_cmd_id",
    ),
    (
        "nwk_srcextendedaddr--aps_frametype_cmdid.tsv",
        (
            "nwk_srcextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
            ("!nwk_srcextendedaddr", None),
        ),
        "aps_frametype",
        "aps_cmd_id",
    ),
    (
        "nwk_dstextendedaddr--aps_frametype_cmdid.tsv",
        (
            "nwk_dstextendedaddr",
        ),
        (
            ("error_msg", None),
            ("!aps_frametype", None),
            ("!nwk_dstextendedaddr", None),
        ),
        "aps_frametype",
        "aps_cmd_id",
    ),
])


def distinct_matches(out_dirpath):
    """Compute the distinct matching values for certain conditions."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    logging.info("Computing the distinct matching values for {} conditions..."
                 "".format(len(COLUMN_MATCHES)))
    for column_match in COLUMN_MATCHES:
        # Derive the path of the output file, the varying columns,
        # the matching conditions, and the list of column names
        out_filepath = os.path.join(out_dirpath, column_match[0])
        var_columns = column_match[1]
        conditions = column_match[2]
        column_names = list(column_match[3:])

        # Compute the distinct values of the varying columns
        var_values = config.db.distinct_values(var_columns, conditions)
        var_values.sort(key=config.custom_sorter)

        # Compute the distinct matches for each value
        results = []
        for var_value in var_values:
            var_conditions = list(conditions)
            for i in range(len(var_value)):
                var_conditions.append((var_columns[i], var_value[i]))
            matches = config.db.distinct_values(column_names, var_conditions)
            matches.sort(key=config.custom_sorter)
            results.append((var_value, matches))

        # Write the distinct matches in the output file
        config.fs.write_tsv(results, out_filepath)
