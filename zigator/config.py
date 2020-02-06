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
Configuration script for the zigator package
"""

import logging
import os
import sqlite3
import string

from scapy.all import conf

from . import load


# Define the path of the configuration directory
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "zigator")

# Define the filepaths of configuration files
NETWORK_FILEPATH = os.path.join(CONFIG_DIR, "network_keys.tsv")
LINK_FILEPATH = os.path.join(CONFIG_DIR, "link_keys.tsv")
INSTALL_FILEPATH = os.path.join(CONFIG_DIR, "install_codes.tsv")
DB_FILEPATH = os.path.join(CONFIG_DIR, "traffic.db")

# Define the columns of the table in the database
DB_COLUMNS = [
    ("pcap_directory", "TEXT"),
    ("pcap_filename", "TEXT"),
    ("pkt_num", "INTEGER"),
    ("pkt_raw", "TEXT"),
    ("pkt_show", "TEXT"),
    ("phy_length", "INTEGER"),
    ("mac_fcs", "TEXT"),
    ("mac_frametype", "TEXT"),
    ("mac_security", "TEXT"),
    ("mac_framepending", "TEXT"),
    ("mac_ackreq", "TEXT"),
    ("mac_panidcomp", "TEXT"),
    ("mac_dstaddrmode", "TEXT"),
    ("mac_frameversion", "TEXT"),
    ("mac_srcaddrmode", "TEXT"),
    ("mac_seqnum", "INTEGER"),
    ("mac_dstpanid", "TEXT"),
    ("mac_dstshortaddr", "TEXT"),
    ("mac_dstextendedaddr", "TEXT"),
    ("mac_srcpanid", "TEXT"),
    ("mac_srcshortaddr", "TEXT"),
    ("mac_srcextendedaddr", "TEXT"),
    ("mac_cmd_id", "TEXT"),
    ("mac_assocreq_apc", "TEXT"),
    ("mac_assocreq_devtype", "TEXT"),
    ("mac_assocreq_powsrc", "TEXT"),
    ("mac_assocreq_rxidle", "TEXT"),
    ("mac_assocreq_seccap", "TEXT"),
    ("mac_assocreq_allocaddr", "TEXT"),
    ("mac_assocrsp_shortaddr", "TEXT"),
    ("mac_assocrsp_status", "TEXT"),
    ("mac_disassoc_reason", "TEXT"),
    ("mac_realign_panid", "TEXT"),
    ("mac_realign_coordaddr", "TEXT"),
    ("mac_realign_channel", "INTEGER"),
    ("mac_realign_shortaddr", "TEXT"),
    ("mac_realign_page", "INTEGER"),
    ("mac_gtsreq_length", "INTEGER"),
    ("mac_gtsreq_dir", "TEXT"),
    ("mac_gtsreq_chartype", "TEXT"),
    ("mac_beacon_beaconorder", "INTEGER"),
    ("mac_beacon_sforder", "INTEGER"),
    ("mac_beacon_finalcap", "INTEGER"),
    ("mac_beacon_ble", "INTEGER"),
    ("mac_beacon_pancoord", "INTEGER"),
    ("mac_beacon_assocpermit", "INTEGER"),
    ("mac_beacon_gtsnum", "INTEGER"),
    ("mac_beacon_gtspermit", "INTEGER"),
    ("mac_beacon_gtsmask", "INTEGER"),
    ("mac_beacon_nsap", "INTEGER"),
    ("mac_beacon_neap", "INTEGER"),
    ("nwk_beacon_protocolid", "INTEGER"),
    ("nwk_beacon_stackprofile", "INTEGER"),
    ("nwk_beacon_protocolversion", "TEXT"),
    ("nwk_beacon_routercap", "INTEGER"),
    ("nwk_beacon_devdepth", "INTEGER"),
    ("nwk_beacon_edcap", "INTEGER"),
    ("nwk_beacon_epid", "TEXT"),
    ("nwk_beacon_txoffset", "INTEGER"),
    ("nwk_beacon_updateid", "INTEGER"),
    ("nwk_frametype", "TEXT"),
    ("nwk_protocolversion", "TEXT"),
    ("nwk_discroute", "TEXT"),
    ("nwk_multicast", "TEXT"),
    ("nwk_security", "TEXT"),
    ("nwk_srcroute", "TEXT"),
    ("nwk_extendeddst", "TEXT"),
    ("nwk_extendedsrc", "TEXT"),
    ("nwk_edinitiator", "TEXT"),
    ("nwk_dstshortaddr", "TEXT"),
    ("nwk_srcshortaddr", "TEXT"),
    ("nwk_radius", "INTEGER"),
    ("nwk_seqnum", "INTEGER"),
    ("nwk_dstextendedaddr", "TEXT"),
    ("nwk_srcextendedaddr", "TEXT"),
    ("nwk_srcroute_relaycount", "INTEGER"),
    ("nwk_srcroute_relayindex", "INTEGER"),
    ("nwk_srcroute_relaylist", "TEXT"),
    ("nwk_aux_seclevel", "TEXT"),
    ("nwk_aux_keytype", "TEXT"),
    ("nwk_aux_extnonce", "TEXT"),
    ("nwk_aux_framecounter", "INTEGER"),
    ("nwk_aux_srcaddr", "TEXT"),
    ("nwk_aux_keyseqnum", "INTEGER"),
    ("nwk_aux_deckey", "TEXT"),
    ("nwk_aux_decsrc", "TEXT"),
    ("nwk_aux_decpayload", "TEXT"),
    ("nwk_aux_decshow", "TEXT"),
    ("nwk_cmd_id", "TEXT"),
    ("nwk_routerequest_mto", "TEXT"),
    ("nwk_routerequest_ed", "TEXT"),
    ("nwk_routerequest_mc", "TEXT"),
    ("nwk_routerequest_id", "INTEGER"),
    ("nwk_routerequest_dstshortaddr", "TEXT"),
    ("nwk_routerequest_pathcost", "INTEGER"),
    ("nwk_routerequest_dstextendedaddr", "TEXT"),
    ("nwk_routereply_eo", "TEXT"),
    ("nwk_routereply_er", "TEXT"),
    ("nwk_routereply_mc", "TEXT"),
    ("nwk_routereply_id", "INTEGER"),
    ("nwk_routereply_origshortaddr", "TEXT"),
    ("nwk_routereply_respshortaddr", "TEXT"),
    ("nwk_routereply_pathcost", "INTEGER"),
    ("nwk_routereply_origextendedaddr", "TEXT"),
    ("nwk_routereply_respextendedaddr", "TEXT"),
    ("nwk_networkstatus_code", "TEXT"),
    ("nwk_networkstatus_dstshortaddr", "TEXT"),
    ("nwk_leave_rejoin", "TEXT"),
    ("nwk_leave_request", "TEXT"),
    ("nwk_leave_rmch", "TEXT"),
    ("nwk_routerecord_relaycount", "INTEGER"),
    ("nwk_routerecord_relaylist", "TEXT"),
    ("nwk_rejoinreq_apc", "TEXT"),
    ("nwk_rejoinreq_devtype", "TEXT"),
    ("nwk_rejoinreq_powsrc", "TEXT"),
    ("nwk_rejoinreq_rxidle", "TEXT"),
    ("nwk_rejoinreq_seccap", "TEXT"),
    ("nwk_rejoinreq_allocaddr", "TEXT"),
    ("nwk_rejoinrsp_shortaddr", "TEXT"),
    ("nwk_rejoinrsp_status", "TEXT"),
    ("nwk_linkstatus_count", "INTEGER"),
    ("nwk_linkstatus_first", "TEXT"),
    ("nwk_linkstatus_last", "TEXT"),
    ("nwk_linkstatus_addresses", "TEXT"),
    ("nwk_linkstatus_incomingcosts", "TEXT"),
    ("nwk_linkstatus_outgoingcosts", "TEXT"),
    ("nwk_networkreport_count", "INTEGER"),
    ("nwk_networkreport_type", "TEXT"),
    ("nwk_networkreport_epid", "TEXT"),
    ("nwk_networkreport_info", "TEXT"),
    ("nwk_networkupdate_count", "INTEGER"),
    ("nwk_networkupdate_type", "TEXT"),
    ("nwk_networkupdate_epid", "TEXT"),
    ("nwk_networkupdate_updateid", "INTEGER"),
    ("nwk_networkupdate_newpanid", "TEXT"),
    ("nwk_edtimeoutreq_reqtime", "TEXT"),
    ("nwk_edtimeoutreq_edconf", "INTEGER"),
    ("nwk_edtimeoutrsp_status", "TEXT"),
    ("nwk_edtimeoutrsp_poll", "TEXT"),
    ("nwk_edtimeoutrsp_timeout", "TEXT"),
    ("aps_frametype", "TEXT"),
    ("aps_delmode", "TEXT"),
    ("aps_ackformat", "TEXT"),
    ("aps_security", "TEXT"),
    ("aps_ackreq", "TEXT"),
    ("aps_exthdr", "TEXT"),
    ("aps_dstendpoint", "INTEGER"),
    ("aps_groupaddr", "TEXT"),
    ("aps_clusterid", "TEXT"),
    ("aps_clustername", "TEXT"),
    ("aps_profileid", "TEXT"),
    ("aps_profilename", "TEXT"),
    ("aps_srcendpoint", "INTEGER"),
    ("aps_counter", "INTEGER"),
    ("aps_fragmentation", "TEXT"),
    ("aps_blocknumber", "INTEGER"),
    ("aps_ackbitfield", "INTEGER"),
    ("aps_aux_seclevel", "TEXT"),
    ("aps_aux_keytype", "TEXT"),
    ("aps_aux_extnonce", "TEXT"),
    ("aps_aux_framecounter", "INTEGER"),
    ("aps_aux_srcaddr", "TEXT"),
    ("aps_aux_keyseqnum", "INTEGER"),
    ("aps_aux_deckey", "TEXT"),
    ("aps_aux_decsrc", "TEXT"),
    ("aps_aux_decpayload", "TEXT"),
    ("aps_aux_decshow", "TEXT"),
    ("aps_cmd_id", "TEXT"),
    ("aps_transportkey_stdkeytype", "TEXT"),
    ("aps_transportkey_key", "TEXT"),
    ("aps_transportkey_keyseqnum", "INTEGER"),
    ("aps_transportkey_dstextendedaddr", "TEXT"),
    ("aps_transportkey_srcextendedaddr", "TEXT"),
    ("aps_transportkey_prtextendedaddr", "TEXT"),
    ("aps_transportkey_initflag", "TEXT"),
    ("aps_updatedevice_extendedaddr", "TEXT"),
    ("aps_updatedevice_shortaddr", "TEXT"),
    ("aps_updatedevice_status", "TEXT"),
    ("aps_removedevice_extendedaddr", "TEXT"),
    ("aps_requestkey_reqkeytype", "TEXT"),
    ("aps_requestkey_prtextendedaddr", "TEXT"),
    ("aps_switchkey_keyseqnum", "INTEGER"),
    ("aps_tunnel_dstextendedaddr", "TEXT"),
    ("aps_tunnel_frametype", "TEXT"),
    ("aps_tunnel_delmode", "TEXT"),
    ("aps_tunnel_ackformat", "TEXT"),
    ("aps_tunnel_security", "TEXT"),
    ("aps_tunnel_ackreq", "TEXT"),
    ("aps_tunnel_exthdr", "TEXT"),
    ("aps_tunnel_counter", "INTEGER"),
    ("aps_verifykey_stdkeytype", "TEXT"),
    ("aps_verifykey_extendedaddr", "TEXT"),
    ("aps_verifykey_keyhash", "TEXT"),
    ("aps_confirmkey_status", "TEXT"),
    ("aps_confirmkey_stdkeytype", "TEXT"),
    ("aps_confirmkey_extendedaddr", "TEXT"),
    ("warning_msg", "TEXT"),
    ("error_msg", "TEXT")
]

# Define sets that will be used to construct valid column definitions
ALLOWED_CHARACTERS = set(string.ascii_letters + string.digits + "_")
ALLOWED_TYPES = set(["TEXT", "INTEGER", "REAL", "BLOB"])
CONSTRAINED_COLUMNS = set([
    "pcap_directory",
    "pcap_filename",
    "pkt_num",
    "pkt_raw",
    "pkt_show"
])

# Initialize the global variables
network_keys = {}
link_keys = {}
install_codes = {}
entry = {column[0]: None for column in DB_COLUMNS}
db_connection = None
db_cursor = None


def init(debug):
    global network_keys
    global link_keys
    global install_codes

    # Configure the logging system
    if debug:
        logging.basicConfig(format="[%(levelname)s] %(message)s",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(format="[%(levelname)s] %(message)s",
                            level=logging.INFO)

    # Make sure that the configuration directory exists
    os.makedirs(CONFIG_DIR, exist_ok=True)

    # Load network keys
    network_keys = load.encryption_keys(NETWORK_FILEPATH, optional=True)
    logging.info("Loaded {} network keys".format(len(network_keys)))

    # Load link keys
    link_keys = load.encryption_keys(LINK_FILEPATH, optional=True)
    logging.info("Loaded {} link keys".format(len(link_keys)))

    # Load install codes and derive link keys from them
    install_codes, derived_keys = load.install_codes(INSTALL_FILEPATH,
                                                     optional=True)
    logging.info("Loaded {} install codes".format(len(install_codes)))

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
    logging.info("Added {} link keys that were derived from install codes"
                 "".format(added_keys))

    # Configure Scapy to assume that Zigbee is above the MAC layer
    conf.dot15d4_protocol = "zigbee"


def reset_entries(keep=[]):
    global entry

    # Reset all data entries in the shared dictionary except
    # the ones that were requested to maintain their values
    if keep is None:
        keep = []
    for column_name in entry.keys():
        if column_name not in keep:
            entry[column_name] = None


def initialize_db():
    global db_connection
    global db_cursor

    # Open a connection with the database
    db_connection = sqlite3.connect(DB_FILEPATH)
    db_connection.text_factory = str
    db_cursor = db_connection.cursor()

    # TODO: Stop automatically resetting the table
    #       when its definition becomes stable
    db_cursor.execute("DROP TABLE IF EXISTS packets")
    db_connection.commit()

    # Create a table for the parsed packets, if it doesn't already exist
    table_creation_command = "CREATE TABLE IF NOT EXISTS packets("
    delimiter_needed = False
    for column in DB_COLUMNS:
        if delimiter_needed:
            table_creation_command += ", "
        else:
            delimiter_needed = True

        column_name = column[0]
        column_type = column[1]

        for i in range(len(column_name)):
            if column_name[i] not in ALLOWED_CHARACTERS:
                raise ValueError("The character \"{}\" in the name of the "
                                 "column \"{}\" is not allowed"
                                 "".format(column_name[i], column_name))

        if column_name[0].isdigit():
            raise ValueError("The name of the column \"{}\" is not allowed "
                             "because it starts with a digit"
                             "".format(column_name))

        table_creation_command += column_name

        if column_type not in ALLOWED_TYPES:
            raise ValueError("The column type \"{}\" is not in the "
                             "set of allowed column types {}"
                             "".format(column_type, ALLOWED_TYPES))

        table_creation_command += " " + column_type

        if column_name in CONSTRAINED_COLUMNS:
            table_creation_command += " NOT NULL"
    table_creation_command += ")"

    db_cursor.execute(table_creation_command)
    db_connection.commit()


def insert_pkt_into_database():
    global db_connection
    global db_cursor

    # Insert the parsed data into the database
    db_cursor.execute("INSERT INTO packets VALUES ({})".format(
                            ", ".join("?"*len(DB_COLUMNS))),
                      tuple(entry[column[0]] for column in DB_COLUMNS))
    db_connection.commit()


def finalize_db():
    global db_connection
    global db_cursor

    # Close the connection with the database
    db_connection.close()
    db_connection = None
    db_cursor = None


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
    tmp_keys = load.encryption_keys(filepath, optional=False)
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
    tmp_codes = load.install_codes(filepath, optional=False)
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
