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
    "nwk_aux_framecounter"
    "nwk_aux_decpayload",
    "nwk_aux_decshow",
    "aps_counter",
    "apx_aux_framecounter",
    "aps_aux_decpayload",
    "aps_aux_decshow",
    "aps_tunnel_counter",
    "zdp_seqnum",
    "zcl_seqnum"
])


def solo_frequencies(out_dirpath):
    """Compute the frequency of certain columns in the database table."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    for i, column_name in enumerate(config.COLUMN_NAMES):
        # Ignore certain columns
        if column_name in IGNORED_COLUMNS:
            continue

        # Derive the path of the output file
        out_filepath = os.path.join(
            out_dirpath,
            "{}-{}-frequency.tsv".format(str(i).zfill(3), column_name))

        # Do not count entries with errors,
        # except when we want to count the errors themselves
        if column_name == "error_msg":
            count_errors = True
        else:
            count_errors = False

        # Write the computed frequencies in the output file
        results = config.grouped_count([column_name], count_errors)
        config.write_tsv(results, out_filepath)
