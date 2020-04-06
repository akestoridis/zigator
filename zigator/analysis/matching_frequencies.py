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


CONDITION_MATCHES = set([
    (
        "phy_length--routerequest.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "phy_length--routereply.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "phy_length--networkstatus.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "phy_length--leave.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "phy_length--routerecord.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "phy_length--rejoinreq.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "phy_length--rejoinrsp.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "phy_length--linkstatus.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "phy_length--networkreport.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "phy_length--networkupdate.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "phy_length--edtimeoutreq.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "phy_length--edtimeoutrsp.tsv",
        (
            "phy_length",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routerequest.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routereply.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkstatus.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--leave.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--routerecord.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--rejoinreq.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--rejoinrsp.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--linkstatus.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkreport.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--networkupdate.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--edtimeoutreq.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_cmd_payloadlength--edtimeoutrsp.tsv",
        (
            "nwk_cmd_payloadlength",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "nwk_radius--routerequest.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_radius--routereply.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_radius--networkstatus.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_radius--leave.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_radius--routerecord.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_radius--rejoinreq.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_radius--rejoinrsp.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_radius--linkstatus.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_radius--networkreport.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_radius--networkupdate.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_radius--edtimeoutreq.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_radius--edtimeoutrsp.tsv",
        (
            "nwk_radius",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_nwk_dsttype--routerequest.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "der_nwk_dsttype--routereply.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "der_nwk_dsttype--networkstatus.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "der_nwk_dsttype--leave.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "der_nwk_dsttype--routerecord.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "der_nwk_dsttype--rejoinreq.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "der_nwk_dsttype--rejoinrsp.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "der_nwk_dsttype--linkstatus.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "der_nwk_dsttype--networkreport.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "der_nwk_dsttype--networkupdate.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "der_nwk_dsttype--edtimeoutreq.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "der_nwk_dsttype--edtimeoutrsp.tsv",
        (
            "der_nwk_dsttype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_nwk_srctype--routerequest.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "der_nwk_srctype--routereply.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "der_nwk_srctype--networkstatus.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "der_nwk_srctype--leave.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "der_nwk_srctype--routerecord.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "der_nwk_srctype--rejoinreq.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "der_nwk_srctype--rejoinrsp.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "der_nwk_srctype--linkstatus.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "der_nwk_srctype--networkreport.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "der_nwk_srctype--networkupdate.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "der_nwk_srctype--edtimeoutreq.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "der_nwk_srctype--edtimeoutrsp.tsv",
        (
            "der_nwk_srctype",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "der_mac_dsttype--datarequest_srcshort.tsv",
        (
            "der_mac_dsttype",
        ),
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Data Request"),
            ("mac_srcaddrmode", "Short source MAC address")
        ),
    ),
    (
        "der_mac_srctype--datarequest_srcshort.tsv",
        (
            "der_mac_srctype",
        ),
        (
            ("error_msg", None),
            ("mac_cmd_id", "MAC Data Request"),
            ("mac_srcaddrmode", "Short source MAC address")
        ),
    ),
])


def matching_frequencies(out_dirpath):
    """Compute the matching frequency of certain conditions."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    logging.info("Computing the matching frequency of {} conditions..."
                 "".format(len(CONDITION_MATCHES)))
    for condition_match in CONDITION_MATCHES:
        # Derive the path of the output file, the varying columns,
        # and the matching conditions
        out_filepath = os.path.join(out_dirpath, condition_match[0])
        var_columns = condition_match[1]
        conditions = condition_match[2]

        # Compute the distinct values of the varying columns
        var_values = config.db.fetch_values(var_columns, conditions, True)
        var_values.sort(key=config.custom_sorter)

        # Compute the matching frequency for each set of conditions
        results = []
        for var_value in var_values:
            var_conditions = list(conditions)
            for i in range(len(var_value)):
                var_conditions.append((var_columns[i], var_value[i]))
            matches = config.db.matching_frequency(var_conditions)
            results.append((var_value, matches))

        # Write the matching frequencies in the output file
        config.fs.write_tsv(results, out_filepath)
