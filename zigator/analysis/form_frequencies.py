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


IGNORED_COLUMNS = set([
    "pkt_num",
    "pkt_raw",
    "pkt_show",
    "mac_fcs",
    "mac_seqnum",
    "nwk_seqnum",
    "nwk_aux_framecounter",
    "nwk_aux_decpayload",
    "nwk_aux_decshow",
    "aps_counter",
    "apx_aux_framecounter",
    "aps_aux_decpayload",
    "aps_aux_decshow",
    "aps_tunnel_counter",
    "zdp_seqnum",
    "zcl_seqnum",
])


PACKET_TYPES = set([
    (
        "nwk_routerequest.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
    ),
    (
        "nwk_routereply.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
    ),
    (
        "nwk_networkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
    ),
    (
        "nwk_leave.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Leave"),
        ),
    ),
    (
        "nwk_routerecord.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
    ),
    (
        "nwk_rejoinreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
    ),
    (
        "nwk_rejoinrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
    ),
    (
        "nwk_linkstatus.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
    ),
    (
        "nwk_networkreport.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
    ),
    (
        "nwk_networkupdate.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
    ),
    (
        "nwk_edtimeoutreq.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
    ),
    (
        "nwk_edtimeoutrsp.tsv",
        (
            ("error_msg", None),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
])


def form_frequencies(out_dirpath):
    """Compute the frequency of forms for certain packet types."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    logging.info("Computing the frequency of forms for {} packet types..."
                 "".format(len(PACKET_TYPES)))
    for packet_type in PACKET_TYPES:
        # Derive the path of the output file and the matching conditions
        out_filepath = os.path.join(out_dirpath, packet_type[0])
        conditions = packet_type[1]

        selected_columns = []
        for column_name in config.COLUMN_NAMES:
            # Ignore certain columns
            if column_name in IGNORED_COLUMNS:
                continue
            else:
                selected_columns.append(column_name)

        # Compute the distinct matching values of the selected columns
        form_values = config.distinct_values(selected_columns, conditions)
        form_values.sort(key=config.custom_sorter)

        # Compute the matching frequency for each form
        results = []
        for form_value in form_values:
            form_conditions = list(conditions)
            for i in range(len(form_value)):
                form_conditions.append((selected_columns[i], form_value[i]))
            matches = config.matching_frequency(form_conditions)
            results.append((form_value, matches))

        # Write the frequency of each form in the output file
        config.write_tsv(results, out_filepath)
