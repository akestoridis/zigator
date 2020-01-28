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

import glob
import logging
import os

from .. import config
from .pcap_file import pcap_file


def main(dirpath):
    """Parse all pcap files in the provided directory."""
    config.initialize_db()
    filepaths = glob.glob(os.path.join(dirpath, "*.[pP][cC][aA][pP]"))
    filepaths.sort()
    logging.info("Detected {} pcap files in the directory \"{}\""
                 "".format(len(filepaths), dirpath))
    pcap_counter = 0
    for filepath in filepaths:
        pcap_file(filepath)
        pcap_counter += 1
        logging.info("Parsed {} out of the {} pcap files"
                     "".format(pcap_counter, len(filepaths)))
    config.finalize_db()