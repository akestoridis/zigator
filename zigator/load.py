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

"""
Loading script for the zigator package
"""

import csv
import logging
import os
import string


def network_keys(filepath, optional=False):
    """Load network keys from the provided text file."""
    # Check whether an exception should be raised if the file does not exist
    if not os.path.isfile(filepath):
        if optional:
            return {}
        else:
            raise ValueError("The provided file \"{}\" "
                             "does not exist".format(filepath))

    # Read the provided file line by line
    loaded_keys = {}
    with open(filepath, "r") as fp:
        rows = csv.reader(fp, delimiter="\t")
        for i, row in enumerate(rows, start=1):
            # Sanity check
            if len(row) != 2:
                raise ValueError("Line #{} in \"{}\" should contain "
                                 "2 tab-separated values, not {}"
                                 "".format(i, filepath, len(row)))

            # Extract the key in hexadecimal notation and its name
            key_hex = row[0]
            key_name = row[1]

            # Sanity checks
            if not (len(key_hex) == 32
                    and all(d in string.hexdigits for d in key_hex)):
                raise ValueError("Line #{} in \"{}\" should contain a "
                                 "128-bit key using 32 hexadecimal digits, "
                                 "without any prefix".format(i, filepath))
            elif key_name == "":
                raise ValueError("Line #{} in \"{}\" should contain a unique "
                                 "name for its key".format(i, filepath))
            elif key_name.startswith("_"):
                raise ValueError("Line #{} in \"{}\" contains a key "
                                 "name that starts with \"_\", which "
                                 "is not allowed".format(i, filepath))

            # Convert the hexadecimal representation into a bytes object
            key_bytes = bytes.fromhex(key_hex)

            # Make sure that this key is not already loaded
            if key_bytes in loaded_keys.values():
                logging.warning("The network key {} appears more than once "
                                "in \"{}\"".format(key_bytes.hex(), filepath))
            elif key_name in loaded_keys.keys():
                logging.warning("The network key {} from \"{}\" was ignored "
                                "because its key name \"{}\" is also used by "
                                "the network key {}"
                                "".format(key_bytes.hex(), filepath, key_name,
                                          loaded_keys[key_name].hex()))
            else:
                loaded_keys[key_name] = key_bytes

    return loaded_keys



