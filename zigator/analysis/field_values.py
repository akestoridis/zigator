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


def custom_sorter(var_value):
    str_repr = []
    for i in range(len(var_value)):
        if var_value[i] is None:
            str_repr.append(" "*80)
        elif isinstance(var_value[i], int):
            str_repr.append(str(var_value[i]).zfill(80))
        else:
            str_repr.append(var_value[i].ljust(80))
    return ", ".join(str_repr)


def field_values(out_dirpath):
    """Compute the field values of some packet types in the database table."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    for packet_type in PACKET_TYPES:
        # Derive the path of the output file and the matching conditions
        out_filepath = os.path.join(out_dirpath, packet_type[0])
        conditions = packet_type[1]

        results = []
        for column_name in config.COLUMN_NAMES:
            # Ignore certain columns
            if column_name in IGNORED_COLUMNS:
                continue

            # Compute the distinct values of this column
            var_values = config.distinct_values([column_name], conditions)
            var_values.sort(key=custom_sorter)
            var_values = [var_value[0] for var_value in var_values]

            # Add the distinct values of this column in the list of results
            results.append((column_name, var_values))

        # Write the distinct values of each column in the output file
        config.write_tsv(results, out_filepath)
