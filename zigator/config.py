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
Configuration module for the zigator package
"""

import logging
import os
import string

from scapy.all import conf

from . import db
from . import fs


# Define the path of the configuration directory
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "zigator")

# Define the filepaths of configuration files
NETWORK_FILEPATH = os.path.join(CONFIG_DIR, "network-keys.tsv")
LINK_FILEPATH = os.path.join(CONFIG_DIR, "link-keys.tsv")
INSTALL_FILEPATH = os.path.join(CONFIG_DIR, "install-codes.tsv")

# Initialize the global variables
network_keys = {}
link_keys = {}
install_codes = {}
networks = {}
devices = {}
addresses = {}
pairs = {}
entry = {column_name: None for column_name in db.PKT_COLUMN_NAMES}


def init():
    global network_keys
    global link_keys
    global install_codes

    # Make sure that the configuration directory exists
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # Load network keys
    network_keys = fs.load_enc_keys(NETWORK_FILEPATH, optional=True)
    logging.debug("Loaded {} network keys".format(len(network_keys)))

    # Load link keys
    link_keys = fs.load_enc_keys(LINK_FILEPATH, optional=True)
    logging.debug("Loaded {} link keys".format(len(link_keys)))

    # Load install codes and derive link keys from them
    install_codes, derived_keys = fs.load_install_codes(INSTALL_FILEPATH,
                                                        optional=True)
    logging.debug("Loaded {} install codes".format(len(install_codes)))

    # Add link keys, derived from install codes, that are not already loaded
    added_keys = 0
    for key_name in derived_keys.keys():
        if derived_keys[key_name] in link_keys.values():
            logging.debug("The derived link key {} was already loaded"
                          "".format(derived_keys[key_name].hex()))
        elif key_name in link_keys.keys():
            logging.warning("The derived link key {} was not added because "
                            "its name \"{}\" is also used by the link key {}"
                            "".format(derived_keys[key_name].hex(),
                                      key_name,
                                      link_keys[key_name].hex()))
        else:
            link_keys[key_name] = derived_keys[key_name]
            added_keys += 1
    logging.debug("Added {} link keys that were derived from install codes"
                  "".format(added_keys))

    # Configure Scapy to assume that Zigbee is above the MAC layer
    conf.dot15d4_protocol = "zigbee"


def reset_entries(keep=[]):
    global entry

    # Reset all data entries in the shared dictionary except
    # the ones that were requested to maintain their values
    if keep is None:
        keep = []
    for column_name in db.PKT_COLUMN_NAMES:
        if column_name not in keep:
            entry[column_name] = None


def custom_sorter(var_value):
    str_repr = []
    for i in range(len(var_value)):
        if var_value[i] is None:
            str_repr.append(" "*80)
        elif isinstance(var_value[i], int):
            str_repr.append(str(var_value[i]).zfill(80))
        elif isinstance(var_value[i], str):
            str_repr.append(var_value[i].ljust(80))
        else:
            raise ValueError("Unexpected type: {}".format(type(var_value[i])))
    return ",".join(str_repr)


def update_devices(extendedaddr, macdevtype, nwkdevtype):
    global devices

    # Sanity checks
    if extendedaddr is None:
        raise ValueError("The extended address is required")
    elif macdevtype not in {None, "Full-Function Device",
                            "Reduced-Function Device"}:
        raise ValueError("Unexpected MAC device type")
    elif nwkdevtype not in {None, "Zigbee Coordinator", "Zigbee Router",
                            "Zigbee End Device"}:
        raise ValueError("Unexpected NWK device type")

    # Check whether it is a previously unknown device or not
    if extendedaddr not in devices.keys():
        devices[extendedaddr] = {
            "macdevtype": macdevtype,
            "nwkdevtype": nwkdevtype,
        }
    else:
        # Check whether the device's information should be updated or not
        if macdevtype is not None:
            if devices[extendedaddr]["macdevtype"] is None:
                devices[extendedaddr]["macdevtype"] = macdevtype
            elif devices[extendedaddr]["macdevtype"] != macdevtype:
                if devices[extendedaddr]["macdevtype"] != "Conflicting Data":
                    devices[extendedaddr]["macdevtype"] = "Conflicting Data"
                    logging.warning("Conflicting data for the MAC device "
                                    "type of the device with extended "
                                    "address {}".format(extendedaddr))

        if nwkdevtype is not None:
            if devices[extendedaddr]["nwkdevtype"] is None:
                devices[extendedaddr]["nwkdevtype"] = nwkdevtype
            elif devices[extendedaddr]["nwkdevtype"] != nwkdevtype:
                if devices[extendedaddr]["nwkdevtype"] != "Conflicting Data":
                    devices[extendedaddr]["nwkdevtype"] = "Conflicting Data"
                    logging.warning("Conflicting data for the NWK device "
                                    "type of the device with extended "
                                    "address {}".format(extendedaddr))


def update_pairs(srcaddr, dstaddr, panid, time):
    global pairs

    # Sanity checks
    if panid is None:
        raise ValueError("The PAN ID is required")
    elif srcaddr is None:
        raise ValueError("The source address is required")
    elif dstaddr is None:
        raise ValueError("The destination address is required")
    elif time is None:
        raise ValueError("The arrival time is required")
    elif int(panid, 16) < 0 or int(panid, 16) > 65534:
        # Ignore invalid PAN IDs
        return
    elif int(srcaddr, 16) < 0 or int(srcaddr, 16) > 65527:
        # Ignore invalid source short addresses
        return
    elif int(dstaddr, 16) < 0 or int(dstaddr, 16) > 65527:
        # Ignore invalid destination short addresses
        return

    # Update the shared dictionary of pairs
    if (srcaddr, dstaddr, panid) not in pairs.keys():
        pairs[(srcaddr, dstaddr, panid)] = {
            "first": time,
            "last": time,
        }
    elif time > pairs[(srcaddr, dstaddr, panid)]["last"]:
        pairs[(srcaddr, dstaddr, panid)]["last"] = time
    elif time < pairs[(srcaddr, dstaddr, panid)]["first"]:
        pairs[(srcaddr, dstaddr, panid)]["first"] = time


def map_addresses(shortaddr, panid, extendedaddr):
    global addresses

    # Sanity checks
    if panid is None:
        raise ValueError("The PAN ID of the device is required")
    elif shortaddr is None or extendedaddr is None:
        raise ValueError("Both addresses of the device are required")
    elif int(panid, 16) < 0 or int(panid, 16) > 65534:
        # Ignore invalid PAN IDs
        return
    elif int(shortaddr, 16) < 0 or int(shortaddr, 16) > 65527:
        # Ignore invalid device short addresses
        return

    # Update the shared dictionary of addresses
    if (shortaddr, panid) not in addresses.keys():
        addresses[(shortaddr, panid)] = extendedaddr
    elif addresses[(shortaddr, panid)] != extendedaddr:
        if addresses[(shortaddr, panid)] != "Conflicting Data":
            addresses[(shortaddr, panid)] = "Conflicting Data"
            logging.warning("Conflicting data for the mapping of the "
                            "short address {}, in the PAN with ID {}, to "
                            "an extended address".format(shortaddr, panid))


def map_networks(epid, panid):
    global networks

    # Sanity checks
    if epid is None or panid is None:
        raise ValueError("Both network IDs are required")
    elif int(panid, 16) < 0 or int(panid, 16) > 65534:
        # Ignore invalid PAN IDs
        return

    # Update the shared dictionary of networks
    if epid not in networks.keys():
        networks[epid] = set([panid])
    else:
        networks[epid].add(panid)


def add_encryption_keys(filepath, key_type):
    global network_keys
    global link_keys

    # Distinguish network keys from link keys
    if key_type.lower() == "network":
        loaded_keys = network_keys
        loaded_filepath = NETWORK_FILEPATH
    elif key_type.lower() == "link":
        loaded_keys = link_keys
        loaded_filepath = LINK_FILEPATH
    else:
        raise ValueError("Unknown key type \"{}\"".format(key_type))

    # Add the encryption keys that are not already loaded
    tmp_keys = fs.load_enc_keys(filepath, optional=False)
    added_keys = 0
    for key_name in tmp_keys.keys():
        if tmp_keys[key_name] in loaded_keys.values():
            logging.debug("The encryption key {} from \"{}\" "
                          "was already loaded"
                          "".format(tmp_keys[key_name].hex(), filepath))
        elif key_name in loaded_keys.keys():
            logging.warning("The encryption key {} from \"{}\" "
                            "was not added because its name \"{}\" is "
                            "also used by the encryption key {}"
                            "".format(tmp_keys[key_name].hex(),
                                      filepath,
                                      key_name,
                                      loaded_keys[key_name].hex()))
        else:
            loaded_keys[key_name] = tmp_keys[key_name]
            added_keys += 1

            # Save the encryption key in a configuration file
            with open(loaded_filepath, "a") as fp:
                fp.write("{}\t{}\n".format(loaded_keys[key_name].hex(),
                                           key_name))
    logging.info("Added {} {} keys from \"{}\""
                 "".format(added_keys, key_type.lower(), filepath))


def add_install_codes(filepath):
    global install_codes

    # Add the install codes that are not already loaded
    tmp_codes, _ = fs.load_install_codes(filepath, optional=False)
    added_codes = 0
    for code_name in tmp_codes.keys():
        if tmp_codes[code_name] in install_codes.values():
            logging.debug("The install code {} from \"{}\" was already loaded"
                          "".format(tmp_codes[code_name].hex(), filepath))
        elif code_name in install_codes.keys():
            logging.warning("The install code {} from \"{}\" "
                            "was not added because its name \"{}\" is "
                            "also used by the install code {}"
                            "".format(tmp_codes[code_name].hex(),
                                      filepath,
                                      code_name,
                                      install_codes[code_name].hex()))
        else:
            install_codes[code_name] = tmp_codes[code_name]
            added_codes += 1

            # Save the install code in a configuration file
            with open(INSTALL_FILEPATH, "a") as fp:
                fp.write("{}\t{}\n".format(install_codes[code_name].hex(),
                                           code_name))
    logging.info("Added {} install codes from \"{}\""
                 "".format(added_codes, filepath))


def add_sniffed_key(key_bytes, key_type):
    global network_keys
    global link_keys

    # Distinguish network keys from link keys
    if key_type.lower() == "network":
        loaded_keys = network_keys
    elif key_type.lower() == "link":
        loaded_keys = link_keys
    else:
        raise ValueError("Unknown key type \"{}\"".format(key_type))

    # Add the sniffed key if it is not already loaded
    if key_bytes not in loaded_keys.values():
        # Give it a name
        key_name = "_sniffed_{}".format(len(loaded_keys))

        # Make sure that its name is unique before adding it
        if key_name in loaded_keys.keys():
            logging.warning("The sniffed key {} was not added because "
                            "its name \"{}\" is also used by the {} key {}"
                            "".format(key_bytes.hex(),
                                      key_name,
                                      key_type.lower(),
                                      loaded_keys[key_name].hex()))
        else:
            loaded_keys[key_name] = key_bytes
            logging.info("Added a sniffed {} key: {}"
                         "".format(key_type.lower(), key_bytes.hex()))


def add_config_entry(entry_type, entry_value, entry_name):
    global network_keys
    global link_keys
    global install_codes

    # Make sure that the value does not include the hexadecimal prefix
    if entry_value.startswith("0x"):
        entry_value = entry_value[2:]

    # Make sure that the value does not include any colons
    entry_value = entry_value.replace(":", "")

    # Identify the type of the provided configuration entry
    if entry_type.lower() == "network-key":
        config_entries = network_keys
        config_filepath = NETWORK_FILEPATH
        expected_length = 32
    elif entry_type.lower() == "link-key":
        config_entries = link_keys
        config_filepath = LINK_FILEPATH
        expected_length = 32
    elif entry_type.lower() == "install-code":
        config_entries = install_codes
        config_filepath = INSTALL_FILEPATH
        expected_length = 36
    else:
        raise ValueError("Unknown entry type \"{}\"".format(entry_type))

    # Sanity checks
    if not (len(entry_value) == expected_length
            and all(d in string.hexdigits for d in entry_value)):
        raise ValueError("The value of the configuration entry "
                         "should contain {} hexadecimal digits"
                         "".format(expected_length))
    elif entry_name in {None, ""}:
        raise ValueError("A unique name is required for "
                         "the configuration entry")
    elif entry_name.startswith("_"):
        raise ValueError("The name of the configuration entry "
                         "is not allowed to start with \"_\"")

    # Convert the hexadecimal representation into a bytes object
    entry_bytes = bytes.fromhex(entry_value)

    # Sanity checks
    if entry_bytes in config_entries.values():
        raise ValueError("The {} {} was already loaded"
                         "".format(entry_type.lower().replace("-", " "),
                                   entry_bytes.hex()))
    elif entry_name in config_entries.keys():
        raise ValueError("Could not add the {} {} because its "
                         "name \"{}\" is already used by the {} {}"
                         "".format(entry_type.lower().replace("-", " "),
                                   entry_bytes.hex(),
                                   entry_name,
                                   entry_type.lower().replace("-", " "),
                                   config_entries[entry_name].hex()))

    # If the provided configuration entry is an install code, check its CRC
    if entry_type.lower() == "install-code":
        computed_crc, received_crc = fs.check_crc(entry_bytes)
        if computed_crc != received_crc:
            raise ValueError("The CRC value of the install code {} "
                             "is 0x{:04x}, which does not match the "
                             "computed CRC value 0x{:04x}"
                             "".format(entry_bytes.hex(),
                                       received_crc,
                                       computed_crc))

    # Save the provided configuration entry
    config_entries[entry_name] = entry_bytes
    with open(config_filepath, "a") as fp:
        fp.write("{}\t{}\n".format(config_entries[entry_name].hex(),
                                   entry_name))
    logging.info("Saved the {} {} in the \"{}\" configuration file"
                 "".format(entry_type.lower().replace("-", " "),
                           entry_bytes.hex(),
                           config_filepath))


def rm_config_entry(entry_type, entry_name):
    global network_keys
    global link_keys
    global install_codes

    # Identify the type of the provided configuration entry
    if entry_type.lower() == "network-key":
        config_entries = network_keys
        config_filepath = NETWORK_FILEPATH
    elif entry_type.lower() == "link-key":
        config_entries = link_keys
        config_filepath = LINK_FILEPATH
    elif entry_type.lower() == "install-code":
        config_entries = install_codes
        config_filepath = INSTALL_FILEPATH
    else:
        raise ValueError("Unknown entry type \"{}\"".format(entry_type))

    # Make sure that the provided name is used by a configuration entry
    if entry_name not in config_entries.keys():
        raise ValueError("The name \"{}\" is not used by any {}"
                         "".format(entry_name,
                                   entry_type.lower().replace("-", " ")))

    # Update the corresponding configuration file
    del config_entries[entry_name]
    with open(config_filepath, "w") as fp:
        for tmp_name in config_entries.keys():
            if not tmp_name.startswith("_"):
                fp.write("{}\t{}\n".format(config_entries[tmp_name].hex(),
                                           tmp_name))
    logging.info("Removed the \"{}\" {} from the \"{}\" configuration file"
                 "".format(entry_name,
                           entry_type.lower().replace("-", " "),
                           config_filepath))


def print_config():
    logging.info("Printing the current configuration...")
    print("\nNetwork Keys:")
    for key_name in network_keys.keys():
        print("{}\t{}".format(network_keys[key_name].hex(), key_name))
    print("\nLink Keys:")
    for key_name in link_keys.keys():
        print("{}\t{}".format(link_keys[key_name].hex(), key_name))
    print("\nInstall codes:")
    for code_name in install_codes.keys():
        print("{}\t{}".format(install_codes[code_name].hex(), code_name))
    print("\nConfiguration directory: \"{}\"".format(CONFIG_DIR))
