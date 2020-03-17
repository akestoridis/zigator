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


COLUMN_SELECTIONS = set([
    (
        "mac_datarequest--mac_srcshorttype.tsv",
        (
            "mac_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("mac_srcaddrmode", "Short source MAC address"),
            ("mac_cmd_id", "MAC Data Request"),
        ),
    ),
    (
        "nwk_routerequest--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_routereply--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_networkstatus--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_leave--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_routerecord--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_rejoinrequest--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_rejoinresponse--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_linkstatus--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_networkreport--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_networkupdate--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_edtimeoutreq--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_edtimeoutrsp--nwk_srcshorttype.tsv",
        (
            "nwk_srcshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
    (
        "mac_datarequest--mac_dstshorttype.tsv",
        (
            "mac_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("mac_dstaddrmode", "Short destination MAC address"),
            ("mac_cmd_id", "MAC Data Request"),
        ),
    ),
    (
        "nwk_routerequest--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_routereply--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_networkstatus--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_leave--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_routerecord--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_rejoinrequest--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_rejoinresponse--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_linkstatus--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_networkreport--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_networkupdate--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_edtimeoutreq--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_edtimeoutrsp--nwk_dstshorttype.tsv",
        (
            "nwk_dstshortaddr",
            "mac_dstpanid",
        ),
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
])


def derived_frequencies(out_dirpath):
    """Compute the derived frequencies for the selected columns."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    logging.info("Computing the derived frequencies for {} columns..."
                 "".format(len(COLUMN_SELECTIONS)))
    for column_sel in COLUMN_SELECTIONS:
        # Derive the path of the output file, the selected columns,
        # and the matching conditions
        out_filepath = os.path.join(out_dirpath, column_sel[0])
        selections = column_sel[1]
        conditions = column_sel[2]

        # Compute the distinct values of the selected columns
        raw_matches = config.db.fetch_values(selections, conditions, True)
        raw_matches.sort(key=config.custom_sorter)

        # Compute the frequencies of the derived matches
        results = []
        counters = {}
        for raw_match in raw_matches:
            nwkdevtype = config.db.get_nwkdevtype(shortaddr=raw_match[0],
                                                  panid=raw_match[1],
                                                  extendedaddr=None)
            if nwkdevtype is None:
                nwkdevtype = raw_match[0]

            if nwkdevtype not in counters:
                counters[nwkdevtype] = 1
            else:
                counters[nwkdevtype] += 1
        for nwkdevtype in counters:
            results.append((nwkdevtype, counters[nwkdevtype]))
        results.sort(key=config.custom_sorter)

        # Write the derived frequencies in the output file
        config.fs.write_tsv(results, out_filepath)
