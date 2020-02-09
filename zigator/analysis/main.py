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
from .distinct_matches import distinct_matches
from .field_values import field_values
from .group_frequencies import group_frequencies
from .matching_frequencies import matching_frequencies
from .solo_frequencies import solo_frequencies
from .unique_forms import unique_forms


def main(db_filepath, out_dirpath):
    """Analyze traffic stored in a database file."""
    # Sanity check
    if not os.path.isfile(db_filepath):
        raise ValueError("The provided database file \"{}\" "
                         "does not exist".format(db_filepath))

    # Make sure that the output directory exists
    os.makedirs(out_dirpath, exist_ok=True)

    # Connect to the provided database
    config.connect_to_db(db_filepath)

    # Write the results of each analysis method in the output directory
    solo_frequencies(os.path.join(out_dirpath, "solo-frequencies"))
    group_frequencies(os.path.join(out_dirpath, "group-frequencies"))
    distinct_matches(os.path.join(out_dirpath, "distinct-matches"))
    matching_frequencies(os.path.join(out_dirpath, "matching-frequencies"))
    field_values(os.path.join(out_dirpath, "field-values"))
    unique_forms(os.path.join(out_dirpath, "unique-forms"))

    # Disconnect from the provided database
    config.disconnect_from_db()