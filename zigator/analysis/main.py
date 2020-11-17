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

from .distinct_matches import distinct_matches
from .field_values import field_values
from .form_frequencies import form_frequencies
from .group_frequencies import group_frequencies
from .matching_frequencies import matching_frequencies
from .selected_frequencies import selected_frequencies
from .solo_frequencies import solo_frequencies


def main(db_filepath, out_dirpath, num_workers):
    """Analyze traffic stored in a database file."""
    # Sanity check
    if not os.path.isfile(db_filepath):
        raise ValueError("The provided database file \"{}\" "
                         "does not exist".format(db_filepath))

    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Write the results of each analysis method in the output directory
    logging.info("Analyzing traffic stored in the \"{}\" database..."
                 "".format(db_filepath))
    solo_frequencies(
        db_filepath,
        os.path.join(out_dirpath, "solo-frequencies"),
        num_workers)
    group_frequencies(
        db_filepath,
        os.path.join(out_dirpath, "group-frequencies"),
        num_workers)
    distinct_matches(
        db_filepath,
        os.path.join(out_dirpath, "distinct-matches"),
        num_workers)
    matching_frequencies(
        db_filepath,
        os.path.join(out_dirpath, "matching-frequencies"),
        num_workers)
    field_values(
        db_filepath,
        os.path.join(out_dirpath, "field-values"),
        num_workers)
    form_frequencies(
        db_filepath,
        os.path.join(out_dirpath, "form-frequencies"),
        num_workers)
    selected_frequencies(
        db_filepath,
        os.path.join(out_dirpath, "selected-frequencies"),
        num_workers)
    logging.info("Finished the analysis of the \"{}\" database"
                 "".format(db_filepath))
