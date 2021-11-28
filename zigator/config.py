# Copyright (C) 2020-2021 Dimitrios-Georgios Akestoridis
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
Configuration module for the ``zigator`` package.
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

# Define different types of messages
RETURN_MSG = 0
DEBUG_MSG = 1
INFO_MSG = 2
WARNING_MSG = 3
ERROR_MSG = 4
CRITICAL_MSG = 5
PCAP_MSG = 6
PKT_MSG = 7
NETWORK_KEYS_MSG = 8
LINK_KEYS_MSG = 9
NETWORKS_MSG = 10
SHORT_ADDRESSES_MSG = 11
EXTENDED_ADDRESSES_MSG = 12
PAIRS_MSG = 13

# Initialize the global variables
version = "0+unknown"
network_keys = {}
link_keys = {}
install_codes = {}
networks = {}
short_addresses = {}
extended_addresses = {}
pairs = {}
entry = {column_name: None for column_name in db.PKT_COLUMN_NAMES}


def init(derived_version):
    global version

    # Store the derived version identifier
    version = derived_version

    # Configure the logging system
    logging.basicConfig(
        format="[%(asctime)s %(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO,
    )

    # Configure Scapy to assume that Zigbee is above the MAC layer
    conf.dot15d4_protocol = "zigbee"


def enable_debug_logging():
    logging.getLogger().setLevel(logging.DEBUG)


def load_config_files():
    global network_keys
    global link_keys
    global install_codes

    # This should be the first logging message
    logging.info("Started Zigator version {}".format(version))

    # Make sure that the configuration directory exists
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # Load network keys
    network_keys = fs.load_enc_keys(NETWORK_FILEPATH, optional=True)
    logging.debug("Loaded {} network keys".format(len(network_keys)))

    # Load link keys
    link_keys = fs.load_enc_keys(LINK_FILEPATH, optional=True)
    logging.debug("Loaded {} link keys".format(len(link_keys)))

    # Load install codes and derive link keys from them
    install_codes, derived_keys = fs.load_install_codes(
        INSTALL_FILEPATH,
        optional=True,
    )
    logging.debug("Loaded {} install codes".format(len(install_codes)))

    # Add link keys, derived from install codes, that are not already loaded
    added_keys = 0
    for key_name in derived_keys.keys():
        if derived_keys[key_name] in link_keys.values():
            logging.debug(
                "The derived link key {} was already loaded".format(
                    derived_keys[key_name].hex(),
                ),
            )
        elif key_name in link_keys.keys():
            logging.warning(
                "The derived link key "
                + "{} was not added ".format(derived_keys[key_name].hex())
                + "because its name \"{}\" ".format(key_name)
                + "is also used by the link key "
                + "{}".format(link_keys[key_name].hex()),
            )
        else:
            link_keys[key_name] = derived_keys[key_name]
            added_keys += 1
    logging.debug(
        "Added {} link keys that were derived from install codes".format(
            added_keys,
        ),
    )


def reset_entries(keep=None):
    # Reset all data entries in the dictionary except
    # the ones that were requested to maintain their values
    if keep is None:
        keep = set()
    for column_name in db.PKT_COLUMN_NAMES:
        if column_name not in keep:
            entry[column_name] = None


def set_entry(pkt_column_name, value_index, known_values):
    # Set the corresponding data entry only if the provided value
    # is included in the provided list of known values
    if value_index in known_values.keys():
        entry[pkt_column_name] = known_values[value_index]
        return True
    else:
        return False


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


def update_networks(panid, epidset, earliest, latest):
    # Sanity checks
    if panid is None:
        raise ValueError("The PAN ID is required")
    elif int(panid, 16) < 0 or int(panid, 16) > 65534:
        # Ignore invalid PAN IDs
        return

    # Update the dictionary of networks
    if panid in networks.keys():
        networks[panid]["epidset"] = (
            networks[panid]["epidset"].union(epidset)
        )

        if earliest is not None:
            if networks[panid]["earliest"] is None:
                networks[panid]["earliest"] = earliest
            elif earliest < networks[panid]["earliest"]:
                networks[panid]["earliest"] = earliest

        if latest is not None:
            if networks[panid]["latest"] is None:
                networks[panid]["latest"] = latest
            elif latest > networks[panid]["latest"]:
                networks[panid]["latest"] = latest
    else:
        networks[panid] = {
            "epidset": epidset,
            "earliest": earliest,
            "latest": latest,
        }


def update_short_addresses(
    panid,
    shortaddr,
    altset,
    macset,
    nwkset,
    earliest,
    latest,
):
    # Sanity checks
    if panid is None:
        raise ValueError("The PAN ID is required")
    elif shortaddr is None:
        raise ValueError("The short address is required")
    elif int(panid, 16) < 0 or int(panid, 16) > 65534:
        # Ignore invalid PAN IDs
        return
    elif int(shortaddr, 16) < 0 or int(shortaddr, 16) > 65527:
        # Ignore invalid device short addresses
        return

    # Update the dictionary of short addresses
    if (panid, shortaddr) in short_addresses.keys():
        short_addresses[(panid, shortaddr)]["altset"] = (
            short_addresses[(panid, shortaddr)]["altset"].union(altset)
        )

        short_addresses[(panid, shortaddr)]["macset"] = (
            short_addresses[(panid, shortaddr)]["macset"].union(macset)
        )

        short_addresses[(panid, shortaddr)]["nwkset"] = (
            short_addresses[(panid, shortaddr)]["nwkset"].union(nwkset)
        )

        if earliest is not None:
            if short_addresses[(panid, shortaddr)]["earliest"] is None:
                short_addresses[(panid, shortaddr)]["earliest"] = earliest
            elif earliest < short_addresses[(panid, shortaddr)]["earliest"]:
                short_addresses[(panid, shortaddr)]["earliest"] = earliest

        if latest is not None:
            if short_addresses[(panid, shortaddr)]["latest"] is None:
                short_addresses[(panid, shortaddr)]["latest"] = latest
            elif latest > short_addresses[(panid, shortaddr)]["latest"]:
                short_addresses[(panid, shortaddr)]["latest"] = latest
    else:
        short_addresses[(panid, shortaddr)] = {
            "altset": altset,
            "macset": macset,
            "nwkset": nwkset,
            "earliest": earliest,
            "latest": latest,
        }


def update_extended_addresses(
    extendedaddr,
    altset,
    macset,
    nwkset,
    earliest,
    latest,
):
    # Sanity check
    if extendedaddr is None:
        raise ValueError("The extended address is required")

    # Update the dictionary of extended addresses
    if extendedaddr in extended_addresses.keys():
        extended_addresses[extendedaddr]["altset"] = (
            extended_addresses[extendedaddr]["altset"].union(altset)
        )

        extended_addresses[extendedaddr]["macset"] = (
            extended_addresses[extendedaddr]["macset"].union(macset)
        )

        extended_addresses[extendedaddr]["nwkset"] = (
            extended_addresses[extendedaddr]["nwkset"].union(nwkset)
        )

        if earliest is not None:
            if extended_addresses[extendedaddr]["earliest"] is None:
                extended_addresses[extendedaddr]["earliest"] = earliest
            elif earliest < extended_addresses[extendedaddr]["earliest"]:
                extended_addresses[extendedaddr]["earliest"] = earliest

        if latest is not None:
            if extended_addresses[extendedaddr]["latest"] is None:
                extended_addresses[extendedaddr]["latest"] = latest
            elif latest > extended_addresses[extendedaddr]["latest"]:
                extended_addresses[extendedaddr]["latest"] = latest
    else:
        extended_addresses[extendedaddr] = {
            "altset": altset,
            "macset": macset,
            "nwkset": nwkset,
            "earliest": earliest,
            "latest": latest,
        }


def update_alternative_addresses(panid, shortaddr, extendedaddr):
    if None not in {panid, shortaddr, extendedaddr}:
        update_short_addresses(
            panid,
            shortaddr,
            {
                extendedaddr,
            },
            set(),
            set(),
            None,
            None,
        )
        update_extended_addresses(
            extendedaddr,
            {
                (panid, shortaddr),
            },
            set(),
            set(),
            None,
            None,
        )


def update_devtypes(panid, shortaddr, extendedaddr, macdevtype, nwkdevtype):
    if panid is not None and shortaddr is not None:
        update_short_addresses(
            panid,
            shortaddr,
            set(),
            {macdevtype} if macdevtype is not None else set(),
            {nwkdevtype} if nwkdevtype is not None else set(),
            None,
            None,
        )
    if extendedaddr is not None:
        update_extended_addresses(
            extendedaddr,
            set(),
            {macdevtype} if macdevtype is not None else set(),
            {nwkdevtype} if nwkdevtype is not None else set(),
            None,
            None,
        )


def update_pairs(panid, srcaddr, dstaddr, earliest, latest):
    # Sanity checks
    if panid is None:
        raise ValueError("The PAN ID is required")
    elif srcaddr is None:
        raise ValueError("The source address is required")
    elif dstaddr is None:
        raise ValueError("The destination address is required")
    elif earliest is None:
        raise ValueError("The earliest time is required")
    elif latest is None:
        raise ValueError("The latest time is required")
    elif int(panid, 16) < 0 or int(panid, 16) > 65534:
        # Ignore invalid PAN IDs
        return
    elif int(srcaddr, 16) < 0 or int(srcaddr, 16) > 65527:
        # Ignore invalid source short addresses
        return
    elif int(dstaddr, 16) < 0 or int(dstaddr, 16) > 65527:
        # Ignore invalid destination short addresses
        return

    # Update the dictionary of pairs
    if (panid, srcaddr, dstaddr) in pairs.keys():
        if latest > pairs[(panid, srcaddr, dstaddr)]["latest"]:
            pairs[(panid, srcaddr, dstaddr)]["latest"] = latest

        if earliest < pairs[(panid, srcaddr, dstaddr)]["earliest"]:
            pairs[(panid, srcaddr, dstaddr)]["earliest"] = earliest
    else:
        pairs[(panid, srcaddr, dstaddr)] = {
            "earliest": earliest,
            "latest": latest,
        }


def get_alternative_addresses(panid, shortaddr):
    if (panid, shortaddr) in short_addresses.keys():
        return {
            int(extendedaddr, 16)
            for extendedaddr in short_addresses[(panid, shortaddr)]["altset"]
        }
    else:
        return set()


def get_extendedaddr(panid, shortaddr):
    if (panid, shortaddr) in short_addresses.keys():
        if len(short_addresses[(panid, shortaddr)]["altset"]) == 0:
            return None
        elif len(short_addresses[(panid, shortaddr)]["altset"]) == 1:
            return list(short_addresses[(panid, shortaddr)]["altset"])[0]
        else:
            return "Conflicting Data"
    else:
        return None


def get_nwkdevtype(panid, shortaddr, extendedaddr):
    nwkset = set()

    if (panid, shortaddr) in short_addresses.keys():
        nwkset = nwkset.union(short_addresses[(panid, shortaddr)]["nwkset"])
        if len(nwkset) > 1:
            return "Conflicting Data"

    if extendedaddr in extended_addresses.keys():
        nwkset = nwkset.union(extended_addresses[extendedaddr]["nwkset"])

    if len(nwkset) == 0:
        return None
    elif len(nwkset) == 1:
        return list(nwkset)[0]
    else:
        return "Conflicting Data"


def update_derived_entries():
    # Update previously unknown MAC Destination extended addresses
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_mac_dstpanid",
            "der_mac_dstshortaddr",
        ],
        [
            ("error_msg", None),
            ("!der_mac_dstpanid", None),
            ("!der_mac_dstshortaddr", None),
            ("!der_mac_dstshortaddr", "0xffff"),
            ("der_mac_dstextendedaddr", None),
        ],
        True,
    )
    for (panid, shortaddr) in fetched_tuples:
        extendedaddr = get_extendedaddr(panid, shortaddr)
        if extendedaddr is not None:
            db.update_packets(
                [
                    "der_mac_dstextendedaddr",
                ],
                [
                    extendedaddr,
                ],
                [
                    ("error_msg", None),
                    ("der_mac_dstpanid", panid),
                    ("der_mac_dstshortaddr", shortaddr),
                    ("der_mac_dstextendedaddr", None),
                ],
            )

    # Update previously unknown MAC Source extended addresses
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_mac_srcpanid",
            "der_mac_srcshortaddr",
        ],
        [
            ("error_msg", None),
            ("!der_mac_srcpanid", None),
            ("!der_mac_srcshortaddr", None),
            ("der_mac_srcextendedaddr", None),
        ],
        True,
    )
    for (panid, shortaddr) in fetched_tuples:
        extendedaddr = get_extendedaddr(panid, shortaddr)
        if extendedaddr is not None:
            db.update_packets(
                [
                    "der_mac_srcextendedaddr",
                ],
                [
                    extendedaddr,
                ],
                [
                    ("error_msg", None),
                    ("der_mac_srcpanid", panid),
                    ("der_mac_srcshortaddr", shortaddr),
                    ("der_mac_srcextendedaddr", None),
                ],
            )

    # Update previously unknown NWK Destination extended addresses
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_nwk_dstpanid",
            "der_nwk_dstshortaddr",
        ],
        [
            ("error_msg", None),
            ("!der_nwk_dstpanid", None),
            ("!der_nwk_dstshortaddr", None),
            ("!der_nwk_dstshortaddr", "0xffff"),
            ("!der_nwk_dstshortaddr", "0xfffd"),
            ("!der_nwk_dstshortaddr", "0xfffc"),
            ("!der_nwk_dstshortaddr", "0xfffb"),
            ("der_nwk_dstextendedaddr", None),
        ],
        True,
    )
    for (panid, shortaddr) in fetched_tuples:
        extendedaddr = get_extendedaddr(panid, shortaddr)
        if extendedaddr is not None:
            db.update_packets(
                [
                    "der_nwk_dstextendedaddr",
                ],
                [
                    extendedaddr,
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_dstpanid", panid),
                    ("der_nwk_dstshortaddr", shortaddr),
                    ("der_nwk_dstextendedaddr", None),
                ],
            )

    # Update previously unknown NWK Source extended addresses
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_nwk_srcpanid",
            "der_nwk_srcshortaddr",
        ],
        [
            ("error_msg", None),
            ("!der_nwk_srcpanid", None),
            ("!der_nwk_srcshortaddr", None),
            ("der_nwk_srcextendedaddr", None),
        ],
        True,
    )
    for (panid, shortaddr) in fetched_tuples:
        extendedaddr = get_extendedaddr(panid, shortaddr)
        if extendedaddr is not None:
            db.update_packets(
                [
                    "der_nwk_srcextendedaddr",
                ],
                [
                    extendedaddr,
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_srcpanid", panid),
                    ("der_nwk_srcshortaddr", shortaddr),
                    ("der_nwk_srcextendedaddr", None),
                ],
            )

    # Update previously unknown MAC Destination types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_mac_dstpanid",
            "der_mac_dstshortaddr",
            "der_mac_dstextendedaddr",
        ],
        [
            ("error_msg", None),
            ("der_mac_dsttype", "MAC Dst Type: None"),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype is not None:
            db.update_packets(
                [
                    "der_mac_dsttype",
                ],
                [
                    "MAC Dst Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_mac_dstpanid", panid),
                    ("der_mac_dstshortaddr", shortaddr),
                    ("der_mac_dstextendedaddr", extendedaddr),
                ],
            )

    # Update previously unknown MAC Source types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_mac_srcpanid",
            "der_mac_srcshortaddr",
            "der_mac_srcextendedaddr",
        ],
        [
            ("error_msg", None),
            ("der_mac_srctype", "MAC Src Type: None"),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype is not None:
            db.update_packets(
                [
                    "der_mac_srctype",
                ],
                [
                    "MAC Src Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_mac_srcpanid", panid),
                    ("der_mac_srcshortaddr", shortaddr),
                    ("der_mac_srcextendedaddr", extendedaddr),
                ],
            )

    # Update previously unknown NWK Destination types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_nwk_dstpanid",
            "der_nwk_dstshortaddr",
            "der_nwk_dstextendedaddr",
        ],
        [
            ("error_msg", None),
            ("der_nwk_dsttype", "NWK Dst Type: None"),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype is not None:
            db.update_packets(
                [
                    "der_nwk_dsttype",
                ],
                [
                    "NWK Dst Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_dstpanid", panid),
                    ("der_nwk_dstshortaddr", shortaddr),
                    ("der_nwk_dstextendedaddr", extendedaddr),
                ],
            )

    # Update previously unknown NWK Source types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_nwk_srcpanid",
            "der_nwk_srcshortaddr",
            "der_nwk_srcextendedaddr",
        ],
        [
            ("error_msg", None),
            ("der_nwk_srctype", "NWK Src Type: None"),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype is not None:
            db.update_packets(
                [
                    "der_nwk_srctype",
                ],
                [
                    "NWK Src Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_srcpanid", panid),
                    ("der_nwk_srcshortaddr", shortaddr),
                    ("der_nwk_srcextendedaddr", extendedaddr),
                ],
            )

    # Check for conflicting extended addresses
    for (panid, shortaddr) in short_addresses.keys():
        if len(short_addresses[(panid, shortaddr)]["altset"]) > 1:
            db.update_packets(
                [
                    "der_mac_dstextendedaddr",
                ],
                [
                    "Conflicting Data",
                ],
                [
                    ("error_msg", None),
                    ("der_mac_dstpanid", panid),
                    ("der_mac_dstshortaddr", shortaddr),
                ],
            )
            db.update_packets(
                [
                    "der_mac_srcextendedaddr",
                ],
                [
                    "Conflicting Data",
                ],
                [
                    ("error_msg", None),
                    ("der_mac_srcpanid", panid),
                    ("der_mac_srcshortaddr", shortaddr),
                ],
            )
            db.update_packets(
                [
                    "der_nwk_dstextendedaddr",
                ],
                [
                    "Conflicting Data",
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_dstpanid", panid),
                    ("der_nwk_dstshortaddr", shortaddr),
                ],
            )
            db.update_packets(
                [
                    "der_nwk_srcextendedaddr",
                ],
                [
                    "Conflicting Data",
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_srcpanid", panid),
                    ("der_nwk_srcshortaddr", shortaddr),
                ],
            )

    # Check for conflicting MAC Destination types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_mac_dstpanid",
            "der_mac_dstshortaddr",
            "der_mac_dstextendedaddr",
        ],
        [
            ("error_msg", None),
            ("!der_mac_dstshortaddr", "0xffff"),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype == "Conflicting Data":
            db.update_packets(
                [
                    "der_mac_dsttype",
                ],
                [
                    "MAC Dst Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_mac_dstpanid", panid),
                    ("der_mac_dstshortaddr", shortaddr),
                    ("der_mac_dstextendedaddr", extendedaddr),
                ],
            )

    # Check for conflicting MAC Source types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_mac_srcpanid",
            "der_mac_srcshortaddr",
            "der_mac_srcextendedaddr",
        ],
        [
            ("error_msg", None),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype == "Conflicting Data":
            db.update_packets(
                [
                    "der_mac_srctype",
                ],
                [
                    "MAC Src Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_mac_srcpanid", panid),
                    ("der_mac_srcshortaddr", shortaddr),
                    ("der_mac_srcextendedaddr", extendedaddr),
                ],
            )

    # Check for conflicting NWK Destination types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_nwk_dstpanid",
            "der_nwk_dstshortaddr",
            "der_nwk_dstextendedaddr",
        ],
        [
            ("error_msg", None),
            ("!der_nwk_dstshortaddr", "0xffff"),
            ("!der_nwk_dstshortaddr", "0xfffd"),
            ("!der_nwk_dstshortaddr", "0xfffc"),
            ("!der_nwk_dstshortaddr", "0xfffb"),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype == "Conflicting Data":
            db.update_packets(
                [
                    "der_nwk_dsttype",
                ],
                [
                    "NWK Dst Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_dstpanid", panid),
                    ("der_nwk_dstshortaddr", shortaddr),
                    ("der_nwk_dstextendedaddr", extendedaddr),
                ],
            )

    # Check for conflicting NWK Source types
    fetched_tuples = db.fetch_values(
        "packets",
        [
            "der_nwk_srcpanid",
            "der_nwk_srcshortaddr",
            "der_nwk_srcextendedaddr",
        ],
        [
            ("error_msg", None),
        ],
        True,
    )
    for (panid, shortaddr, extendedaddr) in fetched_tuples:
        nwkdevtype = get_nwkdevtype(panid, shortaddr, extendedaddr)
        if nwkdevtype == "Conflicting Data":
            db.update_packets(
                [
                    "der_nwk_srctype",
                ],
                [
                    "NWK Src Type: {}".format(nwkdevtype),
                ],
                [
                    ("error_msg", None),
                    ("der_nwk_srcpanid", panid),
                    ("der_nwk_srcshortaddr", shortaddr),
                    ("der_nwk_srcextendedaddr", extendedaddr),
                ],
            )


def add_new_key(key_bytes, key_type, key_name):
    # Distinguish network keys from link keys
    if key_type.lower() == "network":
        loaded_keys = network_keys
    elif key_type.lower() == "link":
        loaded_keys = link_keys
    else:
        raise ValueError("Unknown key type \"{}\"".format(key_type))

    # Make sure that the provided key is not already loaded
    if key_bytes not in loaded_keys.values():
        # Make sure that its name is unique before adding it
        if key_name in loaded_keys.keys():
            return (
                "The key {} was not added because ".format(key_bytes.hex())
                + "its name \"{}\" is also used ".format(key_name)
                + "by the {} key ".format(key_type.lower())
                + "{}".format(loaded_keys[key_name].hex())
            )
        else:
            loaded_keys[key_name] = key_bytes
    return None


def add_config_entry(entry_type, entry_value, entry_name):
    # Make sure that the value does not include the hexadecimal prefix
    if entry_value.startswith("0x"):
        entry_value = entry_value[2:]

    # Make sure that the value does not include any colons
    entry_value = entry_value.replace(":", "")

    # Identify the type of the provided configuration entry
    if entry_type == "network-key":
        config_entries = network_keys
        config_filepath = NETWORK_FILEPATH
        expected_length = 32
    elif entry_type == "link-key":
        config_entries = link_keys
        config_filepath = LINK_FILEPATH
        expected_length = 32
    elif entry_type == "install-code":
        config_entries = install_codes
        config_filepath = INSTALL_FILEPATH
        expected_length = 36
    else:
        raise ValueError("Unknown entry type \"{}\"".format(entry_type))

    # Sanity checks
    if not (
        len(entry_value) == expected_length
        and all(d in string.hexdigits for d in entry_value)
    ):
        raise ValueError(
            "The value of the configuration entry "
            + "should contain {} hexadecimal digits".format(expected_length),
        )
    elif entry_name in {None, ""}:
        raise ValueError(
            "A unique name is required for the configuration entry",
        )
    elif entry_name.startswith("_"):
        raise ValueError(
            "The name of the configuration entry "
            + "is not allowed to start with \"_\"",
        )

    # Convert the hexadecimal representation into a bytes object
    entry_bytes = bytes.fromhex(entry_value)

    # Sanity checks
    if entry_bytes in config_entries.values():
        raise ValueError(
            "The {} {} was already loaded".format(
                entry_type.replace("-", " "),
                entry_bytes.hex(),
            ),
        )
    elif entry_name in config_entries.keys():
        raise ValueError(
            "Could not add the {} ".format(entry_type.replace("-", " "))
            + "{} because its name ".format(entry_bytes.hex())
            + "\"{}\" is already used by the ".format(entry_name)
            + "{} ".format(entry_type.replace("-", " "))
            + "{}".format(config_entries[entry_name].hex()),
        )

    # If the provided configuration entry is an install code, check its CRC
    if entry_type == "install-code":
        computed_crc, received_crc = fs.check_crc(entry_bytes)
        if computed_crc != received_crc:
            raise ValueError(
                "The CRC value of the install code "
                + "{} is ".format(entry_bytes.hex())
                + "0x{:04x}, ".format(received_crc)
                + "which does not match the computed CRC value "
                + "0x{:04x}".format(computed_crc),
            )

    # Save the provided configuration entry
    config_entries[entry_name] = entry_bytes
    with open(config_filepath, mode="a", encoding="utf-8") as fp:
        fp.write(
            "{}\t{}\n".format(config_entries[entry_name].hex(), entry_name),
        )
    logging.info(
        "Saved the {} {} in the \"{}\" configuration file".format(
            entry_type.replace("-", " "),
            entry_bytes.hex(),
            config_filepath,
        ),
    )


def rm_config_entry(entry_type, entry_name):
    # Identify the type of the provided configuration entry
    if entry_type == "network-key":
        config_entries = network_keys
        config_filepath = NETWORK_FILEPATH
    elif entry_type == "link-key":
        config_entries = link_keys
        config_filepath = LINK_FILEPATH
    elif entry_type == "install-code":
        config_entries = install_codes
        config_filepath = INSTALL_FILEPATH
    else:
        raise ValueError("Unknown entry type \"{}\"".format(entry_type))

    # Make sure that the provided name is used by a configuration entry
    if entry_name not in config_entries.keys():
        raise ValueError(
            "The name \"{}\" is not used by any {}".format(
                entry_name,
                entry_type.replace("-", " "),
            ),
        )

    # Update the corresponding configuration file
    del config_entries[entry_name]
    with open(config_filepath, mode="w", encoding="utf-8") as fp:
        for tmp_name in config_entries.keys():
            if not tmp_name.startswith("_"):
                fp.write(
                    "{}\t{}\n".format(
                        config_entries[tmp_name].hex(),
                        tmp_name,
                    ),
                )
    logging.info(
        "Removed the \"{}\" {} from the \"{}\" configuration file".format(
            entry_name,
            entry_type.replace("-", " "),
            config_filepath,
        ),
    )


def print_config():
    logging.info("Printing the current configuration...")
    print("Network keys:")
    for key_name in sorted(network_keys.keys()):
        print("{}\t{}".format(network_keys[key_name].hex(), key_name))
    print("\nLink keys:")
    for key_name in sorted(link_keys.keys()):
        print("{}\t{}".format(link_keys[key_name].hex(), key_name))
    print("\nInstall codes:")
    for code_name in sorted(install_codes.keys()):
        print("{}\t{}".format(install_codes[code_name].hex(), code_name))
    print("\nConfiguration directory: \"{}\"".format(CONFIG_DIR))
