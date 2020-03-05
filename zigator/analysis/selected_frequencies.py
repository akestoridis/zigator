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


CONDITION_SELECTIONS = set([
    (
        "packet_types.tsv",
        (
            "MAC Acknowledgment",
            ("error_msg", None),
            ("mac_frametype", "MAC Acknowledgment"),
        ),
        (
            "MAC Beacon",
            ("error_msg", None),
            ("mac_frametype", "MAC Beacon"),
        ),
        (
            "MAC Command",
            ("error_msg", None),
            ("mac_frametype", "MAC Command"),
        ),
        (
            "NWK Command",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
        ),
        (
            "APS Acknowledgment",
            ("error_msg", None),
            ("aps_frametype", "APS Acknowledgment"),
        ),
        (
            "APS Command",
            ("error_msg", None),
            ("aps_frametype", "APS Command"),
        ),
        (
            "ZDP Command",
            ("error_msg", None),
            ("aps_frametype", "APS Data"),
            ("aps_profilename", "Zigbee Device Profile (ZDP)"),
        ),
        (
            "ZCL Command",
            ("error_msg", None),
            ("aps_frametype", "APS Data"),
            ("!aps_profilename", "Zigbee Device Profile (ZDP)"),
        ),
    ),
    (
        "encrypted_nwk_commands.tsv",
        (
            "NWK Route Request",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Route Request"),
        ),
        (
            "NWK Route Reply",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Route Reply"),
        ),
        (
            "NWK Network Status",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Network Status"),
        ),
        (
            "NWK Leave",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Leave"),
        ),
        (
            "NWK Route Record",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Route Record"),
        ),
        (
            "NWK Rejoin Request",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Rejoin Request"),
        ),
        (
            "NWK Rejoin Response",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Rejoin Response"),
        ),
        (
            "NWK Link Status",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Link Status"),
        ),
        (
            "NWK Network Report",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Network Report"),
        ),
        (
            "NWK Network Update",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK Network Update"),
        ),
        (
            "NWK End Device Timeout Request",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK End Device Timeout Request"),
        ),
        (
            "NWK End Device Timeout Response",
            ("error_msg", None),
            ("nwk_frametype", "NWK Command"),
            ("nwk_security", "NWK Security Enabled"),
            ("nwk_cmd_id", "NWK End Device Timeout Response"),
        ),
    ),
])


def selected_frequencies(out_dirpath):
    """Compute the frequency of selected conditions."""
    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    logging.info("Computing the frequency of {} condition selections..."
                 "".format(len(CONDITION_SELECTIONS)))
    for condition_selection in CONDITION_SELECTIONS:
        # Derive the path of the output file and the selected conditions
        out_filepath = os.path.join(out_dirpath, condition_selection[0])
        selections = condition_selection[1:]

        # Compute the matching frequency of each selection
        results = []
        for selection in selections:
            name = selection[0]
            conditions = selection[1:]
            matches = config.db.matching_frequency(conditions)
            results.append((name, matches))

        # Write the matching frequencies in the output file
        config.fs.write_tsv(results, out_filepath)
