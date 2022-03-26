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

from .. import config
from ..enums import Protocol
from .network_graphs import network_graphs


def main(db_filepath, out_dirpath):
    """Visualize traffic stored in a database file."""
    # Make sure that the expected networking protocol is supported
    if config.nwk_protocol not in {Protocol.ZIGBEE}:
        raise ValueError(
            "Unsupported networking protocol for visualization purposes: "
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

    # Connect to the provided database
    logging.info(
        "Visualizing traffic stored in the \"{}\" database...".format(
            db_filepath,
        ),
    )
    config.db.connect(db_filepath)

    # Write the results of each visualization method in the output directory
    network_graphs(os.path.join(out_dirpath, "network-graphs"))

    # Disconnect from the provided database
    logging.info(
        "Finished the visualization of the \"{}\" database".format(
            db_filepath,
        ),
    )
    config.db.disconnect()
