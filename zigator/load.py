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

from pycrc.algorithms import Crc

from . import crypto


def encryption_keys(filepath, optional=False):
    """Load encryption keys from the provided text file."""
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
                raise ValueError("Line #{} in \"{}\" should contain "
                                 "a 128-bit encryption key using "
                                 "32 hexadecimal digits, without any prefix"
                                 "".format(i, filepath))
            elif key_name == "":
                raise ValueError("Line #{} in \"{}\" should contain a unique "
                                 "name for its key".format(i, filepath))
            elif key_name.startswith("_"):
                raise ValueError("Line #{} in \"{}\" contains a key name "
                                 "that starts with \"_\", which is "
                                 "not allowed".format(i, filepath))

            # Convert the hexadecimal representation into a bytes object
            key_bytes = bytes.fromhex(key_hex)

            # Make sure that this encryption key is not already loaded
            if key_bytes in loaded_keys.values():
                logging.warning("The encryption key {} appears "
                                "more than once in \"{}\""
                                "".format(key_bytes.hex(), filepath))
            elif key_name in loaded_keys.keys():
                logging.warning("The encryption key {} from \"{}\" "
                                "was ignored because its name \"{}\" is "
                                "also used by the encryption key {}"
                                "".format(key_bytes.hex(),
                                          filepath,
                                          key_name,
                                          loaded_keys[key_name].hex()))
            else:
                loaded_keys[key_name] = key_bytes

    return loaded_keys


def install_codes(filepath, optional=False):
    """Load install codes from the provided text file and derive link keys."""
    # Check whether an exception should be raised if the file does not exist
    if not os.path.isfile(filepath):
        if optional:
            return {}, {}
        else:
            raise ValueError("The provided file \"{}\" "
                             "does not exist".format(filepath))

    # Initialize the CRC algorithm
    crc = Crc(width=16, poly=0x1021,
              reflect_in=True, xor_in=0xffff,
              reflect_out=True, xor_out=0xffff)

    # Read the provided file line by line
    loaded_codes = {}
    derived_keys = {}
    with open(filepath, "r") as fp:
        rows = csv.reader(fp, delimiter="\t")
        for i, row in enumerate(rows, start=1):
            # Sanity check
            if len(row) != 2:
                raise ValueError("Line #{} in \"{}\" should contain "
                                 "2 tab-separated values, not {}"
                                 "".format(i, filepath, len(row)))

            # Extract the install code in hexadecimal notation and its name
            code_hex = row[0]
            code_name = row[1]

            # Sanity checks
            if not (len(code_hex) == 36
                    and all(d in string.hexdigits for d in code_hex)):
                raise ValueError("Line #{} in \"{}\" should contain "
                                 "a 144-bit install code using "
                                 "36 hexadecimal digits, without any prefix"
                                 "".format(i, filepath))
            elif code_name == "":
                raise ValueError("Line #{} in \"{}\" should contain a unique "
                                 "name for its code".format(i, filepath))
            elif code_name.startswith("_"):
                raise ValueError("Line #{} in \"{}\" contains a code name "
                                 "that starts with \"_\", which is "
                                 "not allowed".format(i, filepath))

            # Convert the hexadecimal representation into a bytes object
            code_bytes = bytes.fromhex(code_hex)

            # Separate the 128-bit number from its CRC value
            received_number = code_bytes[0:16]
            received_crc = int.from_bytes(code_bytes[16:18],
                                          byteorder="little")

            # Compute the CRC value of the received number
            computed_crc = crc.bit_by_bit_fast(received_number)

            # Compare the computed CRC value with the received CRC value
            if computed_crc != received_crc:
                logging.warning("Ignoring the install code {} because "
                                "its CRC value {} does not match the "
                                "computed CRC value {}"
                                "".format(code_bytes.hex(),
                                          hex(received_crc),
                                          hex(computed_crc)))
                continue

            # Make sure that this install code is not already loaded
            if code_bytes in loaded_codes.values():
                logging.warning("The install code {} appears "
                                "more than once in \"{}\""
                                "".format(code_bytes.hex(), filepath))
            elif code_name in loaded_codes.keys():
                logging.warning("The install code {} from \"{}\" "
                                "was ignored because its name \"{}\" is "
                                "also used by the install code {}"
                                "".format(code_bytes.hex(),
                                          filepath,
                                          code_name,
                                          loaded_codes[code_name].hex()))
            else:
                loaded_codes[code_name] = code_bytes

                # Derive the link key and give it a unique name
                key_bytes = crypto.zigbee_mmo_hash(code_bytes)
                key_name = "_derived_{}".format(code_bytes.hex())
                derived_keys[key_name] = key_bytes
                logging.info("Derived the link key {} from the install code "
                             "{}".format(key_bytes.hex(), code_bytes.hex()))

    return loaded_codes, derived_keys
