# Copyright (C) 2020-2022 Dimitrios-Georgios Akestoridis
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

from . import constants
from .. import config
from ..enums import (
    Protocol,
    Table,
)
from .battery_percentages import battery_percentages
from .battery_statuses import battery_statuses
from .time_series import time_series
from .distinct_matches import distinct_matches
from .field_values import field_values
from .form_frequencies import form_frequencies
from .group_frequencies import group_frequencies
from .matching_frequencies import matching_frequencies
from .selected_frequencies import selected_frequencies
from .solo_frequencies import solo_frequencies


def main(db_filepath, out_dirpath, num_workers):
    """Analyze traffic stored in a database file."""
    # Make sure that the expected networking protocol is supported
    if config.nwk_protocol == Protocol.ZIGBEE:
        tablename = Table.ZIGBEE_PACKETS.value
        packets_column_names = config.db.ZIGBEE_PACKETS_COLUMN_NAMES
        ignored_columns = constants.ZIGBEE_IGNORED_COLUMNS
        column_groups = constants.ZIGBEE_COLUMN_GROUPS
        column_matches = constants.ZIGBEE_COLUMN_MATCHES
        condition_matches = constants.ZIGBEE_CONDITION_MATCHES
        packet_types = constants.ZIGBEE_PACKET_TYPES
        included_columns = constants.ZIGBEE_INCLUDED_COLUMNS
        condition_selections = constants.ZIGBEE_CONDITION_SELECTIONS
    elif config.nwk_protocol == Protocol.THREAD:
        tablename = Table.THREAD_PACKETS.value
        packets_column_names = config.db.THREAD_PACKETS_COLUMN_NAMES
        ignored_columns = constants.THREAD_IGNORED_COLUMNS
        column_groups = constants.THREAD_COLUMN_GROUPS
        column_matches = constants.THREAD_COLUMN_MATCHES
        condition_matches = constants.THREAD_CONDITION_MATCHES
        packet_types = constants.THREAD_PACKET_TYPES
        included_columns = constants.THREAD_INCLUDED_COLUMNS
        condition_selections = constants.THREAD_CONDITION_SELECTIONS
    else:
        raise ValueError(
            "Unsupported networking protocol for analysis purposes: "
            + "{}".format(config.nwk_protocol),
        )

    # Sanity check
    if not os.path.isfile(db_filepath):
        raise ValueError(
            "The provided database file \"{}\" does not exist".format(
                db_filepath,
            ),
        )

    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Write the results of each analysis method in the output directory
    logging.info(
        "Analyzing traffic stored in the \"{}\" database...".format(
            db_filepath,
        ),
    )
    solo_frequencies(
        db_filepath,
        tablename,
        packets_column_names,
        ignored_columns,
        os.path.join(out_dirpath, "solo-frequencies"),
        num_workers,
    )
    group_frequencies(
        db_filepath,
        tablename,
        column_groups,
        os.path.join(out_dirpath, "group-frequencies"),
        num_workers,
    )
    distinct_matches(
        db_filepath,
        tablename,
        column_matches,
        os.path.join(out_dirpath, "distinct-matches"),
        num_workers,
    )
    matching_frequencies(
        db_filepath,
        tablename,
        condition_matches,
        os.path.join(out_dirpath, "matching-frequencies"),
        num_workers,
    )
    field_values(
        db_filepath,
        tablename,
        packets_column_names,
        ignored_columns,
        packet_types,
        os.path.join(out_dirpath, "field-values"),
        num_workers,
    )
    form_frequencies(
        db_filepath,
        tablename,
        packets_column_names,
        included_columns,
        packet_types,
        os.path.join(out_dirpath, "form-frequencies"),
        num_workers,
    )
    selected_frequencies(
        db_filepath,
        tablename,
        condition_selections,
        os.path.join(out_dirpath, "selected-frequencies"),
        num_workers,
    )
    if config.nwk_protocol == Protocol.ZIGBEE:
        battery_percentages(
            db_filepath,
            tablename,
            os.path.join(out_dirpath, "battery-percentages"),
        )
        battery_statuses(
            db_filepath,
            tablename,
            os.path.join(out_dirpath, "battery-statuses"),
        )
    time_series(
        db_filepath,
        tablename,
        os.path.join(out_dirpath, "time-series"),
        num_workers,
    )
    logging.info(
        "Finished the analysis of the \"{}\" database".format(db_filepath),
    )
