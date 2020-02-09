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


COLUMN_GROUPS = set([
    (
        "security-frequency.tsv",
        "mac_security",
        "nwk_security",
        "aps_security",
    ),
    (
        "keytype-frequency.tsv",
        "nwk_aux_keytype",
        "aps_aux_keytype",
    ),
    (
        "frametype-frequency.tsv",
        "mac_frametype",
        "nwk_frametype",
        "aps_frametype",
        "aps_profilename",
        "zcl_frametype",
    ),
    (
        "frametype_cmdid-frequency.tsv",
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
])


def group_frequencies(out_dirpath):
    """Compute the frequency of values for certain column groups."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    logging.info("Computing the frequency of values for {} column groups..."
                 "".format(len(COLUMN_GROUPS)))
    for column_group in COLUMN_GROUPS:
        # Derive the path of the output file and the list of column names
        out_filepath = os.path.join(out_dirpath, column_group[0])
        column_names = column_group[1:]

        # Do not count entries with errors,
        # except when we want to count the errors themselves
        if "error_msg" in column_names:
            count_errors = True
        else:
            count_errors = False

        # Write the computed frequencies in the output file
        results = config.grouped_count(column_names, count_errors)
        config.write_tsv(results, out_filepath)
